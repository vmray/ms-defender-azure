"""
Main file for azure function execution
"""

import logging as log
import traceback
from datetime import datetime
from hashlib import sha256
from io import BytesIO
from json import dumps

import azure.functions as func
from azure.storage.blob import BlobServiceClient

from .const import (
    ALERT,
    DEFENDER_API,
    GENERAL_CONFIG,
    INDICATOR,
    IngestionConfig,
    AVEnrichment,
    EDREnrichment,
    VMRay_CONFIG,
    MACHINE_ACTION,
)
from .lib.MicrosoftDefender import MicrosoftDefender
from .lib.Models import Machine, TimeoutStatus
from .lib.VMRay import VMRay


def group_evidences_by_machines(evidences):
    """
    Helper function to group evidences by machine
    :param evidences: dict of evidence objects
    :return machines: list of machine objects which contains related evidences
    """
    machines = {}
    for evidence in evidences.values():
        selected_machine_id = list(evidence.machine_ids)[0]

        if selected_machine_id not in machines:
            machines[selected_machine_id] = Machine(selected_machine_id)

        machine = machines[selected_machine_id]
        if evidence.detection_source == ALERT.WINDOWS_DEFENDER_AV:
            machine.av_evidences[evidence.sha256] = evidence
        else:
            machine.edr_evidences[evidence.sha256] = evidence

    return list(machines.values())


def update_evidence_machine_ids(machines):
    """
    Group Evidences By Machine
    :param machines:
    :return: List of Machines
    """
    evidences_by_machine = {}

    for machine in machines:
        for evidence in machine.av_evidences.values():
            evidences_by_machine.setdefault(evidence.sha256, set()).add(machine.id)
            evidence.machine_ids = evidences_by_machine[evidence.sha256]
        for evidence in machine.edr_evidences.values():
            evidences_by_machine.setdefault(evidence.sha256, set()).add(machine.id)
            evidence.machine_ids = evidences_by_machine[evidence.sha256]

    return machines


def list_all_blob(machines):
    """
    List all file(blob) uploaded by powershell scripts during the AV alerts.
    Return list of file object and delete the blob from container.
    """
    file_objects = []
    try:
        for machine in machines:
            if not machine.run_script_live_response_finished:
                continue

            blob_service_client = BlobServiceClient.from_connection_string(
                DEFENDER_API.CONNECTION_STRING
            )
            container_client = blob_service_client.get_container_client(
                DEFENDER_API.CONTAINER_NAME
            )
            blobs = container_client.list_blobs()

            for blob in blobs:
                blob_data = (
                    container_client.get_blob_client(blob.name)
                    .download_blob()
                    .readall()
                )
                sha256_hash = sha256(blob_data).hexdigest()
                file_obj = BytesIO(blob_data)
                file_obj.name = blob.name
                file_objects.append({sha256_hash: file_obj})
                container_client.delete_blob(blob.name)
        log.info("Fetched %d blobs", len(file_objects))

    except Exception as ex:
        log.error("Error getting blobs: %s", ex)

    return file_objects


def run(alert, threat_name, detection_source, timeout_status):
    """
    :param alert:
    :param threat_name:
    :param detection_source:
    :param timeout_status:
    :return: VMRay Result
    """
    result = {}
    ms_defender = MicrosoftDefender(log)
    vmray = VMRay(log)

    found_evidences, download_evidences, resubmit_evidences = {}, {}, {}

    evidences = ms_defender.get_evidences(alert.get("id"))

    for sha256_hash in evidences:
        sample = vmray.get_sample(sha256_hash)
        if sample:
            evidence_metadata = vmray.parse_sample_data(sample)
            if (
                VMRay_CONFIG.RESUBMIT
                and evidence_metadata["sample_verdict"]
                in VMRay_CONFIG.RESUBMISSION_VERDICTS
            ):
                log.info("File %s found in VMRay, will be resubmitted.", sha256_hash)
                evidences[sha256_hash].need_to_submit = True
                resubmit_evidences[sha256_hash] = evidences[sha256_hash]
            else:
                log.info(
                    "File %s found in VMRay. No need to submit again.", sha256_hash
                )
                evidences[sha256_hash].vmray_sample = sample
                found_evidences[sha256_hash] = evidences[sha256_hash]
        else:
            evidences[sha256_hash].need_to_submit = True
            download_evidences[sha256_hash] = evidences[sha256_hash]

    if found_evidences:
        log.info("%d evidences found on VMRay", len(found_evidences))
    if resubmit_evidences:
        log.info("%d evidences will be resubmitted.", len(resubmit_evidences))

    download_evidences.update(resubmit_evidences)

    if download_evidences:
        log.info(
            "%d evidences need to be downloaded and submitted.", len(download_evidences)
        )

    if not VMRay_CONFIG.RESUBMIT:
        for evidence in found_evidences.values():
            sample_data = vmray.parse_sample_data(evidence.vmray_sample)
            if sample_data["sample_verdict"] in GENERAL_CONFIG.SELECTED_VERDICTS:
                child_sample_id = vmray.get_child_samples(sample_data)
                if INDICATOR.ACTIVE:
                    indicator_objects = process_indicators(
                        vmray, ms_defender, child_sample_id, alert.get("id")
                    )
                    if indicator_objects:
                        ms_defender.submit_indicators(indicator_objects)
                    else:  #
                        log.info("No IOC found in vmray to submit")
                if AVEnrichment.ACTIVE.value or EDREnrichment.ACTIVE.value:
                    enrich_alerts(vmray, ms_defender, evidence, child_sample_id)

    machines = group_evidences_by_machines(download_evidences)
    machines = update_evidence_machine_ids(machines)
    log.info("%d machines contain evidences.", len(machines))

    if detection_source == ALERT.WINDOWS_DEFENDER_AV:
        if IngestionConfig.AV_BASED_INGESTION.value:
            if ms_defender.upload_ps_script_to_library():
                machines = ms_defender.run_av_submission_script(
                    machines, timeout_status, threat_name
                )
                if machines:
                    file_objects = list_all_blob(machines)
                    submissions = vmray.submit_av_samples(file_objects)
                    submissions = vmray.get_av_submissions(machines[0], submissions)
                    result = (
                        process_submissions(
                            vmray,
                            ms_defender,
                            submissions,
                            alert,
                            AVEnrichment.ACTIVE.value,
                            timeout_status,
                        )
                        if machines[0].run_script_live_response_finished
                        else {}
                    )

    if detection_source == ALERT.WINDOWS_DEFENDER_ATP:
        if IngestionConfig.EDR_BASED_INGESTION.value:
            machines = ms_defender.run_edr_live_response(machines, timeout_status)
            successful_evidences = [
                evidence
                for machine in machines
                for evidence in machine.get_successful_edr_evidences()
            ]
            log.info(
                "%d evidences successfully collected with live response.",
                len(successful_evidences),
            )

            downloaded_evidences = ms_defender.download_evidences(successful_evidences)
            log.info(
                "%d evidence files downloaded successfully.", len(downloaded_evidences)
            )

            submissions = vmray.submit_samples(downloaded_evidences)
            result = process_submissions(
                vmray,
                ms_defender,
                submissions,
                alert,
                EDREnrichment.ACTIVE.value,
                timeout_status,
            )
    return result


def enrich_alerts(vmray, ms_defender, evidence, child_sample_id):
    """
    :param vmray: VMRay Object
    :param ms_defender: Microsoft Object
    :param evidence: Evidences
    :param child_sample_id: Child Sample ID
    :return: None
    """
    for child_id in child_sample_id:
        vti_data = vmray.get_sample_vtis(child_id)
        sample_vtis = vmray.parse_sample_vtis(vti_data)
        sample_details = vmray.get_sample(child_id, True)
        parse_sample_detail = vmray.parse_sample_data(sample_details)
        ms_defender.enrich_alerts(
            evidence,
            parse_sample_detail,
            sample_vtis,
            AVEnrichment.SELECTED_SECTIONS.value,
        )


def process_indicators(vmray, ms_defender, child_sample_id, alert_id):
    """
    :param vmray: VMRay Object
    :param ms_defender: Microsoft Object
    :param child_sample_id: Child Sample ID
    :param alert_id: Alert ID
    :return: List of indicator object
    """
    indicator_objects = []
    old_indicators = ms_defender.get_indicators()
    for child_id in child_sample_id:
        child_sample_data = vmray.get_sample(child_id, True)
        sha256hash = child_sample_data.get("sample_sha256hash")
        sample_iocs = vmray.get_sample_iocs(child_id)
        ioc_data = vmray.parse_sample_iocs(sample_iocs)
        indicator_objects.extend(
            ms_defender.create_indicator_objects(
                ioc_data, old_indicators, alert_id, sha256hash
            )
        )
    return indicator_objects


def process_submissions(
    vmray, ms_defender, submissions, alert, is_enrich, timeout_status
):
    """
    :param vmray: VMRay Object
    :param ms_defender: Microsoft Object
    :param submissions: Child Sample ID
    :param alert: Alert ID
    :param is_enrich: weather enrich the alert on not
    :param timeout_status: Timeout object
    """
    vmray_result = {}
    for result in vmray.wait_submissions(submissions, timeout_status):
        submission = result["submission"]
        evidence = submission["evidence"]
        vmray.check_submission_error(submission)

        if result["finished"]:
            sample = vmray.get_sample(submission["sample_id"], True)
            sample_data = vmray.parse_sample_data(sample)

            if sample_data["sample_verdict"] in GENERAL_CONFIG.SELECTED_VERDICTS:
                child_sample_id = vmray.get_child_samples(sample_data)
                if INDICATOR.ACTIVE:
                    indicator_objects = process_indicators(
                        vmray, ms_defender, child_sample_id, alert.get("id")
                    )

                    if indicator_objects:
                        ms_defender.submit_indicators(indicator_objects)
                    else:
                        log.info("No IOC found in vmray to submit")
                if is_enrich:
                    enrich_alerts(vmray, ms_defender, evidence, child_sample_id)

            vmray_result[submission["submission_id"]] = {
                "sample_id": sample_data["sample_id"],
                "file_name": sample_data["sample_filename"],
                "verdict": sample_data["sample_verdict"],
                "No_of_indicator_submitted": (
                    len(indicator_objects) if indicator_objects else 0
                ),
                "status": "Pass",
            }

    return vmray_result


def handle_timeout_status(timeout_status, alert):
    """
    :param timeout_status: Timeout status
    :param alert: Alert
    """
    live_response = (
        f"Live response job timeout {MACHINE_ACTION.JOB_TIMEOUT}"
        if timeout_status.live_response_timeout
        else ""
    )
    live_response_status = (
        "Live response job failed for the alert"
        if not timeout_status.live_response_status
        else ""
    )
    return {
        "machine_status_message": f"Machine {alert.get('machineId')} is timeout."
        f" {live_response} {live_response_status}",
        "status": "Fail",
    }


def build_vmray_status(
    vmray_results, timeout_status, machine_status, alert, invocation_id, start_time
):
    """
    :param vmray_results: VMRay Response
    :param timeout_status: Timeout status
    :param machine_status: Machine Status
    :param alert: Alert
    :param invocation_id: Invocation ID
    :param start_time: Start time of alert
    """
    for vmray_submission in timeout_status.vmray_timeout:
        if vmray_submission["timeout"]:
            if len(vmray_results) > 0:
                vmray_results[vmray_submission["submission_id"]]["status"] = "Fail"
                vmray_results[vmray_submission["submission_id"]][
                    "message"
                ] = f"VMRay analysis timeout {VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT}"
            else:
                vmray_results[str([vmray_submission["submission_id"]])] = {
                    "status": "Fail",
                    "message": f"VMRay analysis timeout {VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT}",
                }
    vmray_status_list = []
    for submission_id, value in vmray_results.items():
        vmray_status_list.append(
            {
                "alert_id": alert.get("id"),
                "invocation_id": invocation_id,
                "start_time": start_time,
                "vmray_submission_id": submission_id,
                **value,
                **machine_status,
            }
        )

    if not vmray_results:
        vmray_status_list.append(
            {
                "alert_id": alert.get("id"),
                "invocation_id": invocation_id,
                "start_time": start_time,
                **machine_status,
            }
        )

    return vmray_status_list


def upload_to_blob(alert, vmray_status_list):
    """
    :param alert: Alert object
    :param vmray_status_list: VMRay status list
    """
    blob_service_client = BlobServiceClient.from_connection_string(
        DEFENDER_API.CONNECTION_STRING
    )
    blob_container_client = blob_service_client.get_container_client(
        DEFENDER_API.ALERT_STATUS_CONTAINER_NAME
    )
    blob_client = blob_container_client.get_blob_client(f'{alert.get("id")}.json')
    blob_client.upload_blob(dumps(vmray_status_list), overwrite=True)


def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    """
    Main Function
    """
    log.info("Resource Requested: %s", func.HttpRequest)
    start_time = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")

    try:
        alert = req.params.get("alert") or req.get_json().get("alert")
        threat_name = req.params.get("threat_name") or req.get_json().get("threat_name")
        detection_source = req.params.get("detection_source") or req.get_json().get(
            "detection_source"
        )
        invocation_id = context.invocation_id

        if not alert:
            return func.HttpResponse(
                "Invalid Request. Missing 'alert' parameter.", status_code=400
            )

        log.info(
            "Processing Alert %s and threat_name %s.", alert.get("id"), threat_name
        )

        timeout_status = TimeoutStatus()
        vmray_results = run(alert, threat_name, detection_source, timeout_status)
        machine_status = {
            "machine_status_message": f"Machine {alert.get('machineId')}"
            f" available during the process of evidences",
            "status": "Pass",
        }

        if timeout_status.machine_timeout:
            machine_status = handle_timeout_status(timeout_status, alert)

        vmray_status_list = build_vmray_status(
            vmray_results,
            timeout_status,
            machine_status,
            alert,
            invocation_id,
            start_time,
        )

        upload_to_blob(alert, vmray_status_list)
        return func.HttpResponse(
            dumps({"message": "Successfully submitted and created indicator"}),
            status_code=200,
        )

    except Exception as ex:
        error_msg = traceback.format_exc()
        log.error("Exception Occured: %s", str(ex))
        log.error(error_msg)
        return func.HttpResponse("Internal Server Exception", status_code=500)

