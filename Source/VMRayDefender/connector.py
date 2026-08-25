"""
Main file for azure function execution
"""

import logging as log
import traceback
from hashlib import sha256
from io import BytesIO
from json import dumps
from datetime import datetime, timedelta, timezone
import re

import azure.functions as func
from azure.storage.blob import BlobServiceClient

from .const import (
    ALERT,
    DEFENDER_API,
    GENERAL_CONFIG,
    INDICATOR,
    AVEnrichment,
    EDREnrichment,
    IngestionConfig,
    VMRay_CONFIG,
    REMOVE_SPECIAL_CHAR
)
from .lib.MicrosoftDefender import MicrosoftDefender
from .lib.Models import Machine
from .lib.QuarantineDecrypt import recover_original_file
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
    Read encrypted Defender quarantine artifacts uploaded by the AV PowerShell
    script, decrypt each ResourceData blob with the published mpengine RC4 key,
    keep only the samples whose recovered SHA-256 matches an evidence hash the
    alert actually asked about, and delete every blob touched.
    :param machines: list of Machine objects (av_evidences carries the wanted hashes)
    :return: list of {sha256: BytesIO} dicts, same shape as before
    """
    file_objects = []
    expected_hashes = {
        evidence.sha256.lower()
        for machine in machines
        if machine.run_script_live_response_finished
        for evidence in machine.av_evidences.values()
    }

    if not expected_hashes:
        return file_objects

    # Multiple Defender quarantine entries can hold the same file (re-detections,
    # archive children, etc.). Submit each unique hash only once so VMRay isn't
    # called 9x for one alert — matches the old script's per-hash dedup on the
    # endpoint.
    seen_hashes = set()

    try:
        blob_service_client = BlobServiceClient.from_connection_string(
            DEFENDER_API.CONNECTION_STRING
        )
        container_client = blob_service_client.get_container_client(
            DEFENDER_API.CONTAINER_NAME
        )

        for blob in container_client.list_blobs():
            blob_name = blob.name
            try:
                blob_data = (
                    container_client.get_blob_client(blob_name)
                    .download_blob()
                    .readall()
                )

                # Entries blobs are metadata only; the malware bytes live in
                # ResourceData. Skip Entries (and anything else) but still
                # delete so the container drains.
                if "/ResourceData/" not in blob_name:
                    continue

                original_bytes = recover_original_file(blob_data)
                sha256_hash = sha256(original_bytes).hexdigest().lower()

                if sha256_hash not in expected_hashes:
                    # Recent quarantine entry the alert isn't asking about.
                    continue

                if sha256_hash in seen_hashes:
                    # Same content already collected from another blob.
                    continue
                seen_hashes.add(sha256_hash)

                file_obj = BytesIO(original_bytes)
                file_obj.name = blob_name
                file_objects.append({sha256_hash: file_obj})
            except Exception as ex:
                log.warning("Failed to process blob %s: %s", blob_name, ex)
            finally:
                container_client.delete_blob(blob_name)

        log.info(
            "Recovered %d sample(s) matching alert hashes from quarantine blobs",
            len(file_objects),
        )

    except Exception as ex:
        log.error("Error processing quarantine blobs: %s", ex)

    return file_objects


def run(alert, threat_name, detection_source, threat_family):
    """
    :param alert:
    :param threat_name:
    :param detection_source:
    :param threat_family:
    :return: None
    """
    ms_defender = MicrosoftDefender(log)
    vmray = VMRay(log)

    found_evidences, download_file_evidences, resubmit_file_evidences = {}, {}, {}
    download_url_evidences, resubmit_url_evidences = {}, {}
    submissions = []

    evidences = ms_defender.get_evidences(alert.get("id"))

    for key, evidence in evidences.items():
        if evidence.entity_type == ALERT.EVIDENCE_URL_TYPE:
            existing_sub = vmray.get_submission_by_query(key)
            if len(existing_sub) > 0:
                sample_id = existing_sub[0].get("submission_sample_id")
                sample = vmray.get_sample(sample_id, True)
            else:
                sample = ""
        else:
            sample = vmray.get_sample(key)
        if sample:
            evidence_metadata = vmray.parse_sample_data(sample)
            submission_data = vmray.get_sample_submissions(evidence_metadata)
            evidence.sample_id = evidence_metadata["sample_id"]
            resubmit = sample_age(
                submission_data[0]["submission_created"], VMRay_CONFIG.RESUBMIT
            )
            if (
                resubmit
                and evidence_metadata["sample_verdict"]
                in VMRay_CONFIG.RESUBMISSION_VERDICTS
            ):
                log.info(
                    "Resubmit is set to true, %s will be resubmitted to VMRay for analysis.",
                    key,
                )
                if evidence.entity_type == ALERT.EVIDENCE_FILE_TYPE:
                    resubmit_file_evidences[key] = evidence
                elif evidence.entity_type == ALERT.EVIDENCE_URL_TYPE:
                    resubmit_url_evidences[key] = evidence
            else:
                log.info(
                    "Resubmit is set to False. No need to submit again."
                )
                evidences[key].vmray_sample = sample
                found_evidences[key] = evidences[key]
        else:
            log.info("sample results for %s does not exist in VMRay.", key)
            log.info(
                "%s will be downloaded and submitted to VMRay for analysis.", key
            )
            if evidence.entity_type == ALERT.EVIDENCE_FILE_TYPE:
                download_file_evidences[key] = evidence
            elif evidence.entity_type == ALERT.EVIDENCE_URL_TYPE:
                download_url_evidences[key] = evidence

    if found_evidences:
        log.info("%d evidences found on VMRay", len(found_evidences))
        for evidence in found_evidences.values():
            sample_data = vmray.parse_sample_data(evidence.vmray_sample)
            if sample_data["sample_verdict"] in GENERAL_CONFIG.SELECTED_VERDICTS:
                child_sample_id = vmray.get_child_samples(sample_data)
                if INDICATOR.ACTIVE:
                    indicator_objects = process_indicators(
                        vmray, ms_defender, child_sample_id, evidence
                    )
                    if indicator_objects:
                        ms_defender.submit_indicators(indicator_objects)
                    else:  #
                        log.info("No IOC found in vmray to submit")
                if AVEnrichment.ACTIVE.value or EDREnrichment.ACTIVE.value:
                    enrich_alerts(vmray, ms_defender, evidence, child_sample_id)

    download_file_evidences.update(resubmit_file_evidences)
    download_url_evidences.update(resubmit_url_evidences)

    if download_url_evidences:
        log.info("Alert evidence type URLs are being processed..")
        submissions = process_url(download_url_evidences, vmray, threat_family)
        process_submissions(vmray, ms_defender, submissions, alert.get("id"), True)
        

    if download_file_evidences:
        submissions = process_file(
            download_file_evidences,
            detection_source,
            threat_name,
            ms_defender,
            vmray,
            threat_family,
            alert.get("id")
        )
        process_submissions(vmray, ms_defender, submissions, alert.get("id"), True)
    if VMRay_CONFIG.VMRAY_INCIDENT_TAGS:
        process_incident(evidences, vmray, ms_defender)


def sample_age(created_date: str, resubmit_after: str):
    """
    Function to calculate sample submission time period
    """
    if resubmit_after == 0:
        return True

    sample_created = datetime.fromisoformat(created_date)
    if sample_created.tzinfo is None:
        sample_created = sample_created.replace(tzinfo=timezone.utc)
    current_date = datetime.now(timezone.utc)
    last_submission = current_date - sample_created
    return last_submission >= timedelta(days=int(resubmit_after))

def process_incident(evidences, vmray, ms_defender):
    """ """
    incident_dict = {}
    for _, evidence in evidences.items():
        if evidence.sample_id:
            incident_dict.setdefault(evidence.incident_id, set()).add(evidence.sample_id)
    log.info(f"{incident_dict} will be processed for incident tagging.")
    for inc_id, sample_ids in incident_dict.items():
        log.info(f"Processing incident {inc_id} for samples {sample_ids}")
        # found_malicious = False
        # found_suspicious = False
        threat_families = []
        tags = []
        verdicts = []
        child_sample_objects = []
        for s_id in sample_ids:
            sample_data = vmray.get_sample(s_id, True)
            if sample_data:
                sample_data = vmray.parse_sample_data(sample_data)

                #sample child threat names
                child_samples = vmray.get_child_samples(sample_data)
                for child_id in child_samples:
                    child_sample = vmray.get_sample(child_id, True)
                    child_sample_parsed = vmray.parse_sample_data(child_sample)
                    child_sample_objects.append(child_sample_parsed)
                for x in child_sample_objects:
                    if x and x.get("sample_verdict") != "clean":
                        verdicts.append(x.get("sample_verdict"))
                        threat_families.extend(x.get("sample_threat_names", []))

                # if sample_data and sample_data.get("sample_verdict") == "malicious":
                #     found_malicious = True
                # if sample_data and sample_data.get("sample_verdict") == "suspicious":
                #     found_suspicious = True
                verdicts.append(sample_data.get("sample_verdict"))
                threat_families.extend(sample_data.get("sample_threat_names", []))

        # if found_malicious:
        #     verdict = "#VMRay Malicious"
        # elif found_suspicious:
        #     verdict = "#VMRay Suspicious"
        # else:
        #     verdict = "#VMRay Clean"
        if "malicious" in verdicts:
            tags.append("#VMRay Malicious")
        elif "suspicious" in verdicts:
            tags.append("#VMRay Suspicious")
        elif "clean" in verdicts:
            tags.append("#VMRay Clean")
        


        #remove special characters from threat family names
        threat_families = [s for s in threat_families if not re.search(REMOVE_SPECIAL_CHAR, s) and not s.count('.')>1]

        # tags.append(verdict)
        tags.extend(threat_families)
        tags = list(set(tags))
        if tags:
            ms_defender.update_incident(tags, inc_id)
    return



def process_file(
    download_evidences: dict,
    detection_source: str,
    threat_name: str,
    ms_defender: MicrosoftDefender,
    vmray: VMRay,
    threat_family: str,
    alert_id: str
) -> list:
    """
    Process the EDR and AV alert file
    :param download_evidences:  files to submit
    :param detection_source: Type of alert
    :param threat_name: Name of the threat
    :param ms_defender: MicrosoftDefender Object
    :param vmray: VMRay object
    :param threat_family: Threat Family
    :param alert_id: Alert ID
    """
    log.info(
        "In total %d file evidences need to be"
        " downloaded from defender and submitted to VMRay.",
        len(download_evidences),
    )
    submissions_list = []

    machines = group_evidences_by_machines(download_evidences)
    machines = update_evidence_machine_ids(machines)
    log.info("evidences found on %d machines.", len(machines))
    if detection_source == ALERT.WINDOWS_DEFENDER_AV:
        if IngestionConfig.AV_BASED_INGESTION.value:
            if ms_defender.upload_ps_script_to_library():
                machines = ms_defender.run_av_submission_script(machines, alert_id, threat_name)
                if machines:
                    file_objects = list_all_blob(machines)
                    if len(file_objects) > 0:
                        submissions = vmray.submit_av_samples(file_objects, threat_family, alert_id, download_evidences)
                        submissions_list.extend(vmray.get_av_submissions(machines[0], submissions))
                    else:
                        log.info("AV Alert: No file found to submit")

    if detection_source == ALERT.WINDOWS_DEFENDER_ATP:
        if IngestionConfig.EDR_BASED_INGESTION.value:
            machines = ms_defender.run_edr_live_response(machines, alert_id)
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
            submissions_list.extend(submissions)

    return submissions_list


def process_url(
    download_evidences: dict, vmray: VMRay, threat_family: str
) -> list:
    log.info(
        "In total, %d URL evidences needs to be downloaded and submitted to VMRay.",
        len(download_evidences),
    )
    url_submission = vmray.submit_url(download_evidences, threat_family)
    return url_submission

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
        if VMRay_CONFIG.VMRAY_INCIDENT_COMMENTS:
            ms_defender.enrich_incident(
                evidence,
                parse_sample_detail,
                sample_vtis,
                AVEnrichment.SELECTED_SECTIONS.value,
            )


def process_indicators(vmray, ms_defender, child_sample_id, evidence):
    """
    :param vmray: VMRay Object
    :param ms_defender: Microsoft Object
    :param child_sample_id: Child Sample ID
    :param evidence: Evidence Object
    :return: List of indicator object
    """
    indicator_objects = []
    old_indicators = ms_defender.get_indicators()
    for child_id in child_sample_id:
        child_sample_data = vmray.get_sample(child_id, True)
        sample_url = child_sample_data.get("sample_webif_url")
        sample_created_time = child_sample_data.get("sample_created")
        sample_iocs = vmray.get_sample_iocs(child_id)
        ioc_data = vmray.parse_sample_iocs(sample_iocs)
        indicator_objects.extend(
            ms_defender.create_indicator_objects(
                ioc_data, old_indicators, sample_url, evidence, sample_created_time
            )
        )
    return indicator_objects


def process_submissions(vmray, ms_defender, submissions, alert_id, is_enrich):
    """
    :param vmray: VMRay Object
    :param ms_defender: Microsoft Object
    :param submissions: Child Sample ID
    :param is_enrich: weather enrich the alert on not
    :return: None
    """
    for result in vmray.wait_submissions(submissions):
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
                        vmray, ms_defender, child_sample_id, evidence
                    )

                    if indicator_objects:
                        ms_defender.submit_indicators(indicator_objects)
                    else:
                        log.info("No IOC found in VMRay to submit")
                if is_enrich:
                    enrich_alerts(vmray, ms_defender, evidence, child_sample_id)
        else:
            if submission["comment"]:
                ms_defender.add_comment_to_alert(alert_id, submission["comment"])


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main Function
    """
    log.info("Resource Requested: %s", func.HttpRequest)

    try:
        alert = req.params.get("alert") or req.get_json().get("alert")
        threat_name = req.params.get("threat_name") or req.get_json().get("threat_name")
        threat_family = req.params.get("threat_family") or req.get_json().get(
            "threat_family"
        )
        detection_source = req.params.get("detection_source") or req.get_json().get(
            "detection_source"
        )
        if not alert:
            return func.HttpResponse(
                "Invalid Request. Missing 'alert' parameter.", status_code=400
            )

        log.info(
            "Processing Alert %s and threat_name %s.", alert.get("id"), threat_name
        )

        run(alert, threat_name, detection_source, threat_family)
        return func.HttpResponse(
            dumps({"message": "Successfully submitted and created indicator"}),
            status_code=200,
        )

    except Exception as ex:
        error_msg = traceback.format_exc()
        log.error("Exception Occured: %s", str(ex))
        log.error(error_msg)
        return func.HttpResponse("Internal Server Exception", status_code=500)


