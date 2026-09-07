"""
Microsoft Defender Class
"""

# pylint: disable=line-too-long
# pylint: disable=consider-using-f-string

from base64 import b64encode
from datetime import datetime, timedelta, timezone
from gzip import GzipFile
from io import BytesIO
from json import dumps
from os import path
from string import Template
from time import sleep
import re

import requests
from azure.storage.blob import ContainerSasPermissions, generate_container_sas
from requests_toolbelt.multipart.encoder import MultipartEncoder

from ..const import (
    ALERT,
    AUTH_ERROR_STATUS_CODE,
    DEFENDER_API,
    GRAPH_TO_LEGACY_DETECTION_SOURCE,
    HELPER_SCRIPT_FILE_NAME,
    INDICATOR,
    IOC_FIELD_MAPPINGS,
    MACHINE_ACTION,
    MACHINE_ACTION_STATUS,
    RETRY_STATUS_CODE,
    EnrichmentSectionTypes,
    REMOVE_SPECIAL_CHAR
)
from .Models import Evidence, Indicator


class MicrosoftDefender:
    """
    Wrapper class for Microsoft Defender for Endpoint API calls
    Import this class to retrieve alerts, evidences and start live response jobs
    """

    def __init__(self, log):
        """
        Initialize and authenticate the MicrosoftDefender instance,
        use MicrosoftDefenderConfig as configuration
        :param log: logger instance
        :return: void
        """
        self.access_token = None
        self.headers = None
        self.graph_headers = None
        self.config = DEFENDER_API
        self.log = log
        self._incident_comment_cache = {}

        self.authenticate()
        self.authenticate_graph()

    def authenticate(self):
        """
        Authenticate using Azure Active Directory application properties,
        and retrieves the access token
        :raise: Exception when credentials/application properties are not properly configured
        :return: void
        """

        body = {
            "resource": self.config.RESOURCE_APPLICATION_ID_URI,
            "client_id": self.config.APPLICATION_ID,
            "client_secret": self.config.APPLICATION_SECRET,
            "grant_type": "client_credentials",
        }
        try:
            response = self.retry_request(
                method="POST", url=self.config.AUTH_URL, data=body, auth=True
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.headers = {
                "Authorization": "Bearer %s" % self.access_token,
                "User-Agent": self.config.USER_AGENT,
                "Content-Type": "application/json",
            }
            self.log.info(
                "Successfully authenticated the Microsoft Defender for Endpoint API"
            )
        except Exception as err:
            self.log.error(err)
            raise

    def authenticate_graph(self):
        """
        Authenticate using Azure Active Directory application properties,
        and retrieves the access token
        :raise: Exception when credentials/application properties are not properly configured
        :return: void
        """

        body = {
            "client_id": self.config.APPLICATION_ID,
            "scope": self.config.SOURCE_GRAPH_API,
            "client_secret": self.config.APPLICATION_SECRET,
            "grant_type": "client_credentials",
        }
        try:
            response = self.retry_request(
                method="POST", url=self.config.AUTH_URL.replace("oauth2/token", "oauth2/v2.0/token"), data=body, auth=True
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.graph_headers = {
                "Authorization": "Bearer %s" % self.access_token,
                "User-Agent": self.config.USER_AGENT,
                "Content-Type": "application/json",
            }
            self.log.info(
                "Successfully authenticated the Graph API Microsoft Defender for Office365"
            )
        except Exception as err:
            self.log.error(err)
            raise

    def generate_sas_token(self):
        """
        Generating SAS Token
        :return: Sas Token
        """
        expiry_time = datetime.now(timezone.utc) + timedelta(hours=2)
        sas_token = generate_container_sas(
            account_name=DEFENDER_API.ACCOUNT_NAME,
            container_name=DEFENDER_API.CONTAINER_NAME,
            account_key=DEFENDER_API.ACCOUNT_KEY,
            permission=ContainerSasPermissions(write=True),
            expiry=expiry_time,
        )
        return sas_token

    def upload_ps_script_to_library(self):
        """
        Upload powershell script to Defender library
        """
        request_url = self.config.URL + "/api/libraryfiles"
        sas_token = f"?{self.generate_sas_token()}"
        script_dir = path.dirname(__file__)
        with open(path.join(script_dir, HELPER_SCRIPT_FILE_NAME)) as script_file:
            script_content = script_file.read()
        script_content = Template(script_content)
        updated_sas_token = script_content.safe_substitute(SAS_TOKEN=sas_token)

        mp_encoder = MultipartEncoder(
            fields={
                "HasParameters": "true",
                "OverrideIfExists": "true",
                "Description": "description",
                "file": (HELPER_SCRIPT_FILE_NAME, updated_sas_token, "text/plain"),
            }
        )

        try:
            response = self.retry_request(
                method="POST",
                url=request_url,
                headers={**self.headers, **{"Content-Type": mp_encoder.content_type}},
                data=mp_encoder,
            )
            json_response = response.json()

            if response.ok:
                self.log.info("Helper script successfully uploaded")
                return True
            if "error" in json_response:
                self.log.error(
                    "Failed to upload helper script - Error: %s"
                    % (json_response["error"]["message"])
                )
        except Exception as err:
            self.log.error("Failed to upload helper script - Error: %s" % err)

        return False

    def get_evidences(self, alert_id):
        """
        Retrieve a single alert via Microsoft Graph alerts_v2 and extract
        file/URL evidence into Evidence objects.

        Graph schema differences vs legacy MDE /api/alerts/{id}:
          - Evidence array uses typed @odata.type discriminators
            ('#microsoft.graph.security.fileEvidence', 'urlEvidence',
            'deviceEvidence', etc.) instead of a flat entityType field.
          - File evidence puts sha256/sha1/fileName/filePath under fileDetails.
          - machineId is no longer on the alert; we pull mdeDeviceId from
            the deviceEvidence entry in the evidence array.
          - detectionSource values differ ('microsoftDefenderForEndpoint' /
            'antivirus' instead of 'WindowsDefenderAtp' / 'WindowsDefenderAv').
            We translate back to legacy values via
            GRAPH_TO_LEGACY_DETECTION_SOURCE so downstream comparisons
            against ALERT.WINDOWS_DEFENDER_* and connector.py keep working
            without further changes.

        :param alert_id: Defender alert id
        :return: dict keyed by sha256 or url, of Evidence objects
        """
        request_url = f"{self.config.SECURITY_GRAPH_API}/alerts_v2/{alert_id}"
        evidences: dict = {}

        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.graph_headers
            )
            alert_data = response.json()

            if not alert_data or "error" in alert_data:
                self.log.error(
                    "Failed to retrieve alert %s: %s",
                    alert_id,
                    alert_data.get("error", {}).get("message", "Empty response"),
                )
                return evidences

            # Translate Graph detectionSource enum to legacy value so downstream
            # comparisons (here and in connector.py) keep using the existing
            # ALERT.WINDOWS_DEFENDER_* constants.
            graph_detection_source = alert_data.get("detectionSource")
            detection_source = GRAPH_TO_LEGACY_DETECTION_SOURCE.get(
                graph_detection_source, graph_detection_source
            )

            if detection_source not in ALERT.SELECTED_DETECTION_SOURCES:
                return evidences

            self.log.info(f"Successfully retrieved alert {alert_id}")

            if self.config.FILTER_ALERT_TITLE_WITH:
                title = alert_data.get("title", "").lower()
                if not any(
                    filter_value in title
                    for filter_value in self.config.FILTER_ALERT_TITLE_WITH
                ):
                    self.log.info(
                        f"Skipping alert {alert_id} since its title does not contain any of the filter values provided in FilterAlertTitleWith in configiration"
                    )
                    return evidences

            # machineId moved off the alert top-level in Graph - pull mdeDeviceId
            # from the first deviceEvidence entry in the evidence array.
            machine_id = ""
            for ev in alert_data.get("evidence", []) or []:
                if ev.get("@odata.type") == "#microsoft.graph.security.deviceEvidence":
                    machine_id = ev.get("mdeDeviceId") or ""
                    if machine_id:
                        break

            for evidence in alert_data.get("evidence", []) or []:
                odata_type = evidence.get("@odata.type", "")

                if odata_type == "#microsoft.graph.security.fileEvidence":
                    file_details = evidence.get("fileDetails") or {}
                    evidence_sha256 = file_details.get("sha256") or ""
                    sha1 = file_details.get("sha1") or ""
                    file_name = file_details.get("fileName") or ""
                    file_path = file_details.get("filePath") or ""
                    url = ""
                    entity_type = ALERT.EVIDENCE_FILE_TYPE

                    if not evidence_sha256 or evidence_sha256.lower() == "none":
                        continue

                    if (
                        detection_source == ALERT.WINDOWS_DEFENDER_AV
                        and not DEFENDER_API.FETCH_QUARANTINED_FILES
                    ):
                        self.log.info(
                            f"Skipping file evidence for alert {alert_id} since it's from Windows Defender AV and fetching quarantined files is disabled"
                        )
                        continue
                    key = evidence_sha256

                elif odata_type == "#microsoft.graph.security.urlEvidence":
                    url = (evidence.get("url") or "").strip()
                    if not url:
                        continue
                    evidence_sha256 = ""
                    sha1 = ""
                    file_name = ""
                    file_path = ""
                    entity_type = ALERT.EVIDENCE_URL_TYPE
                    key = url

                else:
                    continue

                evidence_obj = evidences.get(key) or Evidence(
                    sha256=evidence_sha256,
                    sha1=sha1,
                    file_name=file_name,
                    file_path=file_path,
                    alert_id=alert_data["id"],
                    incident_id=str(alert_data.get("incidentId") or ""),
                    machine_id=machine_id,
                    detection_source=detection_source,
                    url=url,
                    entity_type=entity_type,
                )
                evidence_obj.alert_ids.add(alert_data["id"])
                if machine_id:
                    evidence_obj.machine_ids.add(machine_id)
                evidence_obj.set_comments(alert_data.get("comments", []))
                evidences[key] = evidence_obj

            self.log.info("Alert %s - %d evidences found", alert_id, len(evidences))

        except Exception as err:
            self.log.error("Exception while retrieving alert %s: %s", alert_id, err)

        return evidences

    def update_incident(self, tags, incident_id): #["VMRay Malicious"]
        """
        Update incident tags
        """
        self.log.info("Adding tags to the incident id %s" % incident_id)
        try:
            #get tags from incident if any
            request_url = f"{self.config.SECURITY_GRAPH_API}/incidents/{incident_id}"

            incident_resp = self.retry_request(
                method="GET",
                url=request_url,
                headers=self.graph_headers,
            )
            if incident_resp.status_code != 200:
                self.log.error(
                    "Failed to Get incident %s - Error: %s"
                    % (incident_id, incident_resp.content)
                )
            else:
                incident_data = incident_resp.json()
                existing_tags = incident_data.get("customTags", [])
                self.log.info(f"Existing tags for incident {incident_id}: {existing_tags}")
                for tag in tags:
                    if tag not in existing_tags:
                        existing_tags.append(tag) #[maliciouis,clean, "dassfweff"]
                tags = existing_tags


            #tags to have only one vmray verdict
            new_tags = [tag for tag in tags if "#VMRay" not in tag]
            if "#VMRay Malicious" in tags:
                new_tags.append("#VMRay Malicious")
            elif "#VMRay Suspicious" in tags:
                new_tags.append("#VMRay Suspicious")
            elif "#VMRay Clean" in tags:
                new_tags.append("#VMRay Clean")

                
            request_data = {"customTags": new_tags}
            self.log.info(f"Updating incident {incident_id} with tags: {new_tags}")
            response = self.retry_request(
                method="PATCH",
                url=request_url,
                data=dumps(request_data),
                headers=self.graph_headers,
            )

            if response.status_code != 200:
                self.log.error(
                    "Failed to update incident %s - Error: %s"
                    % (incident_id, response.content)
                )
            else:
                self.log.info(f"Successfully update incident {incident_id}")

        except Exception as err:
            self.log.error(
                "Failed to update incident %s - Error: %s" % (incident_id, err)
            )

    def get_machine_actions(self, machine_id):
        """
        Retrieve machine actions for given machine_id
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineactions-collection
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :exception: when machine actions are not properly retrieved
        :return list or None: list of machine actions or None if there is an error
        """
        odata_query = "$filter=machineId+eq+'%s'" % machine_id
        request_url = self.config.URL + "/api/machineactions?" + odata_query
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve actions for machine %s - Error: %s"
                    % (machine_id, json_response["error"]["message"])
                )
                return None
            if "value" in json_response:
                return json_response["value"]
            self.log.error(
                "Failed to parse api response for machine %s - Error: value key not found in dict"
                % (machine_id)
            )
            return None
        except Exception as err:
            self.log.error(
                "Failed to retrieve machine actions for machine %s - Error: %s"
                % (machine_id, err)
            )
            return None

    def get_machine_action(self, live_response_id):
        """
        Retrieve machine action detail with given live_response_id string
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineaction-object
        :param live_response_id: live response id
        :exception: when machine action is not properly retrieved
        :return dict or None: dict of machine action data or None if there is an error
        """
        request_url = self.config.URL + "/api/machineactions/%s" % live_response_id
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve machine action detail for %s - Error: %s"
                    % (live_response_id, json_response["error"]["message"])
                )
                return None
            return json_response
        except Exception as err:
            self.log.error(
                "Failed to retrieve machine action for %s - Error: %s"
                % (live_response_id, err)
            )
            return None

    def is_machine_available(self, machine_id):
        """
        Check if the machine has no pending or processing machine action
        Because we can't make another machine action request when one of them pending
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :return bool: machine availability status
        """
        machine_actions = self.get_machine_actions(machine_id)
        if machine_actions is not None:

            for action in machine_actions:
                if action["status"] in MACHINE_ACTION_STATUS.NOT_AVAILABLE:
                    self.log.warning(
                        "Machine %s is busy. Current action type is %s and status is %s"
                        % (machine_id, action["type"], action["status"])
                    )
                    return False
            self.log.info("Machine %s is available" % machine_id)
            return True
        return False

    def cancel_machine_action(self, live_response_id):
        """
        Cancel the machine action with given live_response object
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cancel-machine-action
        :param live_response: live response instance
        :exception: when machine action is not properly cancelled
        :return bool: status of cancellation request
        """

        is_action_cancelled = False

        while not is_action_cancelled:
            request_url = (
                self.config.URL + "/api/machineactions/%s/cancel" % live_response_id
            )
            try:
                request_data = {
                    "Comment": "Machine action was cancelled by VMRay Connector due to timeout"
                }
                response = self.retry_request(
                    method="POST",
                    url=request_url,
                    data=dumps(request_data),
                    headers=self.headers,
                )
                json_response = response.json()
                if "error" in json_response:
                    self.log.error(
                        "Failed to cancel machine action for %s - Error: %s"
                        % (live_response_id, json_response["error"])
                    )
                else:
                    if (
                        json_response["status"] == "Cancelled"
                        or json_response["status"] == "Failed"
                    ):
                        self.log.info(
                            "Cancelled live response action %s" % live_response_id
                        )
                        is_action_cancelled = True
            except Exception as err:
                self.log.error(
                    "Failed to cancel machine action for %s - Error: %s"
                    % (live_response_id, err)
                )

    def wait_run_script_live_response(self, live_response_id):
        """
        This function checks the live response execution
        :param live_response_id: Live response ID
        :return tuple: status and Machine Action response
        """
        timeout_counter = 0
        has_error = False
        is_finished = False

        self.log.info("Waiting live response job %s to finish" % live_response_id)
        while (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP > timeout_counter
            and not has_error
            and not is_finished
        ):
            sleep(MACHINE_ACTION.JOB_SLEEP)
            machine_action = self.get_machine_action(live_response_id)
            if machine_action is not None:
                if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                    self.log.info("Live response job %s finished" % live_response_id)
                    is_finished = True
                elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                    self.log.error(
                        "Live response job %s failed with error" % live_response_id
                    )
                    has_error = True
                else:
                    timeout_counter += 1
            else:
                has_error = True
        if MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP <= timeout_counter:
            error_message = (
                "Live response job timeout was hit (%s seconds)"
                % MACHINE_ACTION.JOB_TIMEOUT
            )
            self.log.error(
                "Live response job %s failed with error - Error: %s"
                % (live_response_id, error_message)
            )
            has_error = True
            self.cancel_machine_action(live_response_id)
            sleep(MACHINE_ACTION.JOB_SLEEP)

        if has_error:
            return False, machine_action

        return True, machine_action

    def wait_live_response(self, live_response):
        """
        Waiting live response machine action job to finish with configured timeout checks
        :param live_response: live_response object
        :return live_response: modified live_response object with status
        """
        self.log.info("Waiting live response job %s to finish" % live_response.id)
        while (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP
            > live_response.timeout_counter
            and not live_response.has_error
            and not live_response.is_finished
        ):
            sleep(MACHINE_ACTION.JOB_SLEEP)
            machine_action = self.get_machine_action(live_response.id)
            if machine_action is not None:
                if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                    self.log.info("Live response job %s finished" % live_response.id)
                    live_response.status = machine_action["status"]
                    live_response.is_finished = True
                elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                    self.log.error(
                        "Live response job %s failed with error" % live_response.id
                    )
                    live_response.status = machine_action["status"]
                    live_response.has_error = True
                else:
                    live_response.timeout_counter += 1
            else:
                live_response.has_error = True
        if (
            MACHINE_ACTION.JOB_TIMEOUT / MACHINE_ACTION.JOB_SLEEP
            <= live_response.timeout_counter
        ):
            error_message = (
                "Live response job timeout was hit (%s seconds)"
                % MACHINE_ACTION.JOB_TIMEOUT
            )
            self.log.error(
                "Live response job %s failed with error - Error: %s"
                % (live_response.id, error_message)
            )
            live_response.has_error = True
            live_response.status = MACHINE_ACTION_STATUS.TIMEOUT
            self.cancel_machine_action(live_response.id)
            sleep(MACHINE_ACTION.JOB_SLEEP)

        return live_response

    def get_live_response_result(self, live_response):
        """
        Retrieve live response result and download url
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-live-response-result
        :param live_response: live_response object instance
        :exception: when live response result is not properly retrieved
        :return: dict of live response result or None if there is an error
        """
        request_url = (
            self.config.URL
            + "/api/machineactions/%s/GetLiveResponseResultDownloadLink(index=%s)"
            % (live_response.id, live_response.index)
        )
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve live response results for %s - Error: %s"
                    % (live_response.id, json_response["error"]["message"])
                )
                live_response.has_error = True
            else:
                if "value" in json_response:
                    live_response.download_url = json_response["value"]
                else:
                    self.log.error(
                        "Failed to retrieve live response results for"
                        " %s - Error: value key not found" % (live_response.id)
                    )
                    live_response.has_error = True
        except Exception as err:
            self.log.error(
                "Failed to retrieve live response results for %s - Error: %s"
                % (live_response.id, err)
            )
            live_response.has_error = True

        return live_response

    def run_edr_live_response(self, machines, alert_id):
        """
        This function will execute EDR live response command
        :param machines: List of machine contains evidences
        :param alert_id: Alert ID
        """
        for machine in machines:
            if len(machine.edr_evidences) > 0:
                self.log.info(
                    "Waiting %d live response jobs to start for machine %s"
                    % (len(machine.edr_evidences), machine.id)
                )
                while (
                    MACHINE_ACTION.MACHINE_RETRY > machine.timeout_counter
                    and machine.has_pending_edr_actions()
                ):
                    if self.is_machine_available(machine.id):
                        for evidence in machine.edr_evidences.values():
                            if self.is_machine_available(machine.id):
                                # json request body for live response
                                live_response_command = {
                                    "Commands": [
                                        {
                                            "type": "GetFile",
                                            "params": [
                                                {
                                                    "key": "Path",
                                                    "value": evidence.absolute_path,
                                                }
                                            ],
                                        }
                                    ],
                                    "Comment": "VMRay Connector File Acquisition Job for %s"
                                    % evidence.sha256,
                                }

                                self.log.info(
                                    "Trying to start live response job for"
                                    " evidence %s from machine %s"
                                    % (evidence.absolute_path, machine.id)
                                )
                                request_url = (
                                    self.config.URL
                                    + "/api/machines/%s/runliveresponse" % machine.id
                                )
                                try:
                                    response = self.retry_request(
                                        method="POST",
                                        url=request_url,
                                        data=dumps(live_response_command),
                                        headers=self.headers,
                                    )
                                    json_response = response.json()
                                    if "error" in json_response:
                                        self.log.error(
                                            "Live response error for machine %s"
                                            " for evidence %s - Error: %s"
                                            % (
                                                machine.id,
                                                evidence.sha256,
                                                json_response["error"]["message"],
                                            )
                                        )
                                        evidence.live_response.has_error = True
                                    else:
                                        try:
                                            sleep(5)
                                            json_response = self.get_machine_action(
                                                json_response["id"]
                                            )

                                            if json_response is not None:
                                                for command in json_response[
                                                    "commands"
                                                ]:
                                                    if (
                                                        command["command"]["type"]
                                                        == "GetFile"
                                                    ):
                                                        evidence.live_response.index = (
                                                            command["index"]
                                                        )
                                                        evidence.live_response.id = (
                                                            json_response["id"]
                                                        )
                                                self.log.info(
                                                    "Live response job %s for evidence %s started successfully"
                                                    % (
                                                        evidence.live_response.id,
                                                        evidence.sha256,
                                                    )
                                                )
                                                evidence.live_response = (
                                                    self.wait_live_response(
                                                        evidence.live_response
                                                    )
                                                )

                                                if evidence.live_response.is_finished:
                                                    evidence.live_response = (
                                                        self.get_live_response_result(
                                                            evidence.live_response
                                                        )
                                                    )
                                        except Exception as err:
                                            self.log.error(
                                                "Failed to parse api response for machine %s - Error: %s"
                                                % (machine.id, err)
                                            )
                                            evidence.live_response.has_error = True
                                except Exception as err:
                                    self.log.error(
                                        "Failed to create live response job for machine %s - Error: %s"
                                        % (machine.id, err)
                                    )
                                    evidence.live_response.has_error = True
                            else:
                                sleep(MACHINE_ACTION.SLEEP / 60)
                    else:
                        sleep(MACHINE_ACTION.SLEEP)
                        machine.timeout_counter += 1
                if machine.has_pending_edr_actions():
                    comment = (
                        f"Machine {machine.id} was not available"
                        f" during the timeout ({MACHINE_ACTION.MACHINE_TIMEOUT} seconds)"
                    )
                    self.log.error(comment)
                    self.add_comment_to_alert(alert_id, comment)

        return machines

    def run_av_submission_script(self, machines, alert_id, threat_name=""):
        """
        This function will execute AV live response command
        :param machines: List of machine contains evidences
        :param alert_id: Alert ID
        :param threat_name: Threat name from alert response
        """
        for machine in machines:
            file_counter = 0
            live_response_counter = 0
            if len(machine.av_evidences) > 0:
                self.log.info(
                    "Waiting run script live response job to start for machine %s"
                    % machine.id
                )
                file_names = []
                for evidence in machine.av_evidences.values():
                    file_names.append(evidence.sha256)

                while (
                    MACHINE_ACTION.MACHINE_RETRY > machine.timeout_counter
                    and MACHINE_ACTION.MACHINE_RETRY > live_response_counter
                    and not machine.run_script_live_response_finished
                ):
                    if self.is_machine_available(machine.id):
                        args_param = f"{threat_name},{self.config.ACCOUNT_NAME},{self.config.CONTAINER_NAME},{'vmray'.join(file_names)}"
                        live_response_command = {
                            "Commands": [
                                {
                                    "type": "RunScript",
                                    "params": [
                                        {
                                            "key": "ScriptName",
                                            "value": HELPER_SCRIPT_FILE_NAME,
                                        },
                                        {"key": "Args", "value": args_param},
                                    ],
                                }
                            ],
                            "Comment": "Live response job to submit evidences to VMRay",
                        }
                        self.log.info(
                            "Trying to start run script live response job for machine %s"
                            % machine.id
                        )
                        request_url = (
                            self.config.URL
                            + "/api/machines/%s/runliveresponse" % machine.id
                        )
                        try:
                            response = self.retry_request(
                                method="POST",
                                url=request_url,
                                data=dumps(live_response_command),
                                headers=self.headers,
                            )
                            json_response = response.json()
                            if "error" in json_response:
                                self.log.error(
                                    "Run script live response error for machine %s - Error: %s"
                                    % (machine.id, json_response["error"]["message"])
                                )
                            else:
                                self.log.info(
                                    "Run script live response job successfully created for machine %s"
                                    % machine.id
                                )

                                if "id" in json_response:
                                    live_response_id = json_response["id"]
                                    (
                                        result,
                                        machine_action,
                                    ) = self.wait_run_script_live_response(
                                        live_response_id
                                    )
                                    if result:
                                        command = machine_action["commands"][0]
                                        if command["command"]["type"] == "RunScript":
                                            index = command["index"]
                                            res_id = machine_action["id"]
                                            request_url = f"{self.config.URL}/api/machineactions/{res_id}/GetLiveResponseResultDownloadLink(index={index})"
                                            response = self.retry_request(
                                                method="GET",
                                                url=request_url,
                                                headers=self.headers,
                                            )
                                            live_response_result = response.json()
                                            if "error" in live_response_result:
                                                self.log.error(
                                                    "Failed to retrieve live response results for %s - Error: %s"
                                                    % (
                                                        res_id,
                                                        live_response_result["error"][
                                                            "message"
                                                        ],
                                                    )
                                                )
                                            else:
                                                self.log.info(
                                                    "Checking if evidence restore or not"
                                                )
                                                if "value" in live_response_result:
                                                    download_url = live_response_result[
                                                        "value"
                                                    ]
                                                    content = self.retry_request(
                                                        method="GET",
                                                        url=download_url,
                                                        stream=True,
                                                    )
                                                    if content.ok:
                                                        log_msg = content.json().get(
                                                            "script_output"
                                                        )
                                                        if (
                                                            "QuarantinedFilesFound"
                                                            in log_msg
                                                        ):
                                                            self.log.info(
                                                                "Quarantine Files found"
                                                            )
                                                            if (
                                                                "NoMatchFound"
                                                                in log_msg
                                                            ):
                                                                d_msg = (
                                                                    "The evidence hash does"
                                                                    " not match the hash of any quarantined files."
                                                                    "Or defender block the quarantine file during"
                                                                    " hash calculation."
                                                                )
                                                                self.log.info(
                                                                    d_msg
                                                                )
                                                                self.add_comment_to_alert(alert_id, d_msg)
                                                            machine.run_script_live_response_finished = (
                                                                True
                                                            )
                                                        else:
                                                            if file_counter < 1:
                                                                file_counter += 1
                                                                self.log.info(
                                                                    f"No quarantined items for threat {threat_name} found waiting to get the file"
                                                                )
                                                                sleep(300)
                                                                continue
                                                            comment = ("No quarantined files found in the machine."
                                                                       " Microsoft Defender may have already removed"
                                                                       " them from the quarantine folder.")
                                                            self.log.info(
                                                                comment
                                                            )
                                                            self.add_comment_to_alert(alert_id, comment)
                                        machine.run_script_live_response_finished = True
                                        self.log.info(
                                            "Run script live response job successfully finished for machine %s"
                                            % machine.id
                                        )
                                    else:
                                        sleep(MACHINE_ACTION.SLEEP)
                                        live_response_counter += 1
                                        self.log.info(
                                            "Attempting %d Resubmit live response.."
                                            % (live_response_counter)
                                        )
                        except Exception as err:
                            self.log.error(
                                "Failed to create run script live response job for machine %s - Error: %s"
                                % (machine.id, err)
                            )
                            live_response_counter += 1
                    else:
                        # waiting the machine for pending live response jobs
                        sleep(MACHINE_ACTION.SLEEP)
                        # increment timeout_counter to check timeout in While loop
                        machine.timeout_counter += 1

                if MACHINE_ACTION.MACHINE_RETRY <= machine.timeout_counter:
                    comment = (
                        f"Machine {machine.id} was not available during"
                        f" the timeout ({MACHINE_ACTION.MACHINE_TIMEOUT} seconds)"
                    )
                    self.log.error(
                        comment
                    )
                    self.add_comment_to_alert(alert_id, comment)
                if MACHINE_ACTION.MACHINE_RETRY <= live_response_counter:
                    comment = "Live response session failed, maximum retry limit reached."
                    self.log.error(comment)
                    self.add_comment_to_alert(alert_id, comment)

        return machines

    def download_evidences(self, evidences):
        """
        Download and extract evidence files
        :param evidences: list of evidence objects
        :exception: when evidence file is not properly downloaded or extracted
        :return evidences: list of evidence objects with downloaded data in memory
        """

        # Initial list to store successfully downloaded evidences
        downloaded_evidences = []
        self.log.info("Downloading %d evidences" % len(evidences))

        for evidence in evidences:
            if evidence.live_response.download_url is not None:
                self.log.info("Downloading evidence %s" % evidence.sha256)

                try:
                    # Download file as a streaming response
                    response = self.retry_request(
                        method="GET",
                        url=evidence.live_response.download_url,
                        stream=True,
                    )
                    if response.ok:
                        self.log.info(
                            "Evidence %s downloaded successfully. Response code: %d"
                            % (evidence.sha256, response.status_code)
                        )
                        compressed_data = BytesIO(response.content)
                        try:
                            with GzipFile(
                                fileobj=compressed_data, mode="rb"
                            ) as decompressed:
                                evidence.download_file_path = decompressed.read()
                                self.log.info(
                                    "Evidence %s decompressed successfully"
                                    % evidence.sha256
                                )
                                downloaded_evidences.append(evidence)
                        except Exception as err:
                            self.log.error(
                                "Failed to decompress evidence %s - Error: %s"
                                % (evidence.sha256, err)
                            )
                    else:
                        self.log.error(
                            "Failed to download evidence %s - HTTP Status Code: %d"
                            % (evidence.sha256, response.status_code)
                        )
                except Exception as err:
                    self.log.error(
                        "Failed to download evidence %s - Error: %s"
                        % (evidence.sha256, err)
                    )

        return downloaded_evidences

    def get_indicators(self):
        """
        Retrieve unique indicators from Microsoft Defender for Endpoint
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-ti-indicators
        :exception: when indicators are not properly retrieved
        :return indicators: set of indicators
        """
        request_url = self.config.URL + "/api/indicators"
        indicators = set()
        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()
            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve indicators - Error: %s"
                    % json_response["error"]["message"]
                )
            if "value" in json_response:
                for indicator in json_response["value"]:
                    indicators.add(indicator["indicatorValue"])
            else:
                self.log.error(
                    "Failed to retrieve indicators - Error: value key not found"
                )

        except Exception as err:
            self.log.error("Failed to retrieve indicators - Error %s" % err)

        self.log.info("%d unique indicator retrieved in total" % (len(indicators)))

        return indicators

    def create_indicator_objects(
        self, indicator_data, old_indicators, sample_url, evidence, sample_created_time
    ):
        """
        Create indicators objects based on VMRay Analyzer indicator data and retrieved indicators from Microsoft Defender for Endpoint
        :param indicator_data: dict of indicators which retrieved from VMRay submission
        :param old_indicators: set of indicators which retrieved from Microsoft Defender for Endpoint
        :param sample_url: VMRay Sample URL
        :param evidence: Evidence Object
        :param sample_created_time: Sample creation time
        :return indicator_objects: list of indicator objects
        """

        indicator_objects = []
        alerts = ", ".join(evidence.alert_ids)
        generated_by = evidence.sha256 if evidence.entity_type == ALERT.EVIDENCE_FILE_TYPE else evidence.url
        description = (
            f"{INDICATOR.DESCRIPTION}\n"
            f"Alert ID: {alerts}\n"
            f"Generated By {evidence.entity_type} {generated_by}\n"
            f"Sample URL: {sample_url}\n"
            f"Created At: {sample_created_time}"
        )
        for key in indicator_data:
            if key in IOC_FIELD_MAPPINGS.keys():
                for indicator_field in IOC_FIELD_MAPPINGS[key]:
                    indicator_value = indicator_data[key]

                    for indicator in indicator_value:
                        if indicator[0] not in old_indicators:
                            expiration_date = (
                                    datetime.now(timezone.utc)
                                    + timedelta(days=int(INDICATOR.INDICATOREXPIRATION))
                            ).strftime("%Y-%m-%dT%H:%M:%SZ")
                            action = ""
                            if indicator_field in ["Url", "IpAddress", "DomainName"]:
                                action = (
                                    INDICATOR.DEFENDER_INDICATOR_ACTION_FOR_MALICIOUS_IP_URL
                                    if indicator[1] == "malicious"
                                    else INDICATOR.DEFENDER_INDICATOR_ACTION_FOR_SUSPICIOUS_IP_URL
                                )
                            elif indicator_field in [
                                "FileSha256",
                                "FileSha1",
                                "FileMd5",
                            ]:
                                action = (
                                    INDICATOR.DEFENDER_INDICATOR_ACTION_FOR_MALICIOUS_FILE
                                    if indicator[1] == "malicious"
                                    else INDICATOR.DEFENDER_INDICATOR_ACTION_FOR_SUSPICIOUS_FILE
                                )
                            indicator_objects.append(
                                Indicator(
                                    indicator_type=indicator_field,
                                    value=indicator[0],
                                    action=action,
                                    application=self.config.APPLICATION_NAME,
                                    title=INDICATOR.TITLE,
                                    description=description,
                                    verdict=indicator[1],
                                    expirationTime=expiration_date,
                                    generate_alert=INDICATOR.INDICATOR_ALERT,
                                )
                            )

        return indicator_objects

    def submit_indicators(self, indicators):
        """
        Submit indicators to Microsoft Defender for Endpoint
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/post-ti-indicator
        :param indicators: list of indicator objects
        :exception: when indicators are not submitted properly
        :return void:
        """
        self.log.info(
            "%d indicators submitting to Microsoft Defender for Endpoint"
            % len(indicators)
        )
        request_url = self.config.URL + "/api/indicators/import"
        try:
            for i in range(0, len(indicators), INDICATOR.MAX_TI_INDICATORS_PER_REQUEST):
                ind_to_submit = {
                    "Indicators": [
                        indicator.serialize()
                        for indicator in indicators[
                            i : i + INDICATOR.MAX_TI_INDICATORS_PER_REQUEST
                        ]
                    ]
                }
                response = self.retry_request(
                    method="POST",
                    url=request_url,
                    data=dumps(ind_to_submit),
                    headers=self.headers,
                )
                if response.ok:
                    self.log.info(
                        f"{len(indicators)} Indicators submitted successfully"
                    )
                else:
                    self.log.error(
                        "Failed to submit indicator - Error: %s" % response.content
                    )
        except Exception as err:
            self.log.error(f"Failed to submit indicators - Error: {err}")


    def create_comments(self, evidence, sample_data, sample_vtis, enrichment_sections):
        """
        Create comment to enrich alerts with VMRay Analyzer submission metadata
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
        :param evidence: evidence object
        :param sample_data: dict object which contains summary data about the sample
        :param sample_vtis: dict object which contains parsed VTI data about the sample
        :param enrichment_sections: list
        :exception: when alert is not updated properly
        :return comment:
        """
        comment = ""
        threat_names=sample_data.get("sample_threat_names", [])
        threat_names = [s for s in threat_names if not re.search(REMOVE_SPECIAL_CHAR, s) and not s.count('.')>1]

        if sample_data.get("sample_type") != "URL":
            comment = "Evidence SHA256:\n"
            comment += sample_data["sample_sha256hash"] + "\n\n"
        else:
            comment += "Evidence URL:\n"
            comment += evidence.url + "\n\n"

        if sample_data.get("sample_parent_sample_ids"):
            comment += "Child Sample of\n"
            comment += (
                "Sample IDs: "
                + ", ".join(map(str, sample_data.get("sample_parent_sample_ids") or []))
                + "\n\n"
            )
        comment += (
            ("VMRay Verdict: %s\n\n" % sample_data["sample_verdict"].upper())
            if sample_data["sample_verdict"]
            else "VMRay Verdict: N/A\n\n"
        )
        comment += "VMRay analysis" + " (" + sample_data["sample_created"][:10] + ")" + ":\n"
        comment += (
                sample_data["sample_webif_url"]
                + "\n\n"
        )

        if (
            EnrichmentSectionTypes.CLASSIFICATIONS.value in enrichment_sections
            and sample_data["sample_classifications"]
        ):
            comment += "Classifications:\n"
            comment += "\n".join(sample_data["sample_classifications"]) + "\n\n"

        if (
            EnrichmentSectionTypes.THREAT_NAMES.value in enrichment_sections
            and threat_names
        ):
            comment += "Threat Names:\n"
            comment += "\n".join(threat_names) + "\n\n"

        if EnrichmentSectionTypes.VTIS.value in enrichment_sections and sample_vtis:
            comment += "VTI's:\n"
            comment += "\n".join(sample_vtis) + "\n\n"
        if len(comment) > 1000:
            comment = comment[:1000]
        return comment


    def enrich_alerts(self, evidence, sample_data, sample_vtis, enrichment_sections):
        """
        Enrich alerts with VMRay Analyzer submission metadata
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
        :param evidence: evidence object
        :param sample_data: dict object which contains summary data about the sample
        :param sample_vtis: dict object which contains parsed VTI data about the sample
        :param enrichment_sections: list
        :exception: when alert is not updated properly
        :return void:
        """
        comment = ""
        if not sample_data.get("sample_parent_sample_ids"):
            comment = self.create_comments(
                evidence, sample_data, sample_vtis, enrichment_sections
            )
        elif (
                sample_data.get("sample_parent_sample_ids")
                and sample_data.get("sample_verdict") != "clean"
        ):
            comment = self.create_comments(
                evidence, sample_data, sample_vtis, enrichment_sections
            )

        if comment and b64encode(comment.encode("utf-8")).decode("utf-8") not in evidence.comments:
            for alert_id in evidence.alert_ids:
                self.add_comment_to_alert(alert_id, comment)


    def enrich_incident(self, evidence, sample_data, sample_vtis, enrichment_sections):
        """
        Append a VMRay enrichment comment to the parent incident of the given evidence.
        Dedups against comments already present on the incident and against comments
        this process has already appended in the current run (per-instance cache).
        :param evidence: evidence object (must carry incident_id)
        :param sample_data: parsed VMRay sample data
        :param sample_vtis: parsed VMRay VTI data
        :param enrichment_sections: list of enrichment section toggles
        :return: void
        """
        incident_id = getattr(evidence, "incident_id", None)
        if not incident_id:
            return

        comment = ""
        if not sample_data.get("sample_parent_sample_ids"):
            comment = self.create_comments(
                evidence, sample_data, sample_vtis, enrichment_sections
            )
        elif (
            sample_data.get("sample_parent_sample_ids")
            and sample_data.get("sample_verdict") != "clean"
        ):
            comment = self.create_comments(
                evidence, sample_data, sample_vtis, enrichment_sections
            )

        if not comment:
            return

        existing = self._get_incident_comment_digests(incident_id)
        digest = b64encode(comment.encode("utf-8")).decode("utf-8")
        if digest in existing:
            self.log.info(
                f"Skipping incident {incident_id} comment - already present"
            )
            return

        if self.add_comment_to_incident(incident_id, comment):
            existing.add(digest)


    def _get_incident_comment_digests(self, incident_id):
        """
        Return (and lazily populate) the set of base64-encoded comment digests
        already attached to the given incident. Uses a per-instance cache so
        multiple evidences sharing an incident do not re-fetch or double-post.
        """
        if incident_id in self._incident_comment_cache:
            return self._incident_comment_cache[incident_id]

        digests = set()
        try:
            request_url = f"{self.config.SECURITY_GRAPH_API}/incidents/{incident_id}"
            response = self.retry_request(
                method="GET", url=request_url, headers=self.graph_headers
            )
            if response.status_code == 200:
                for item in response.json().get("comments", []) or []:
                    text = item.get("comment")
                    if text:
                        digests.add(
                            b64encode(text.encode("utf-8")).decode("utf-8")
                        )
            else:
                self.log.error(
                    "Failed to get incident %s for comment dedup - Error: %s"
                    % (incident_id, response.content)
                )
        except Exception as err:
            self.log.error(
                "Failed to get incident %s for comment dedup - Error: %s"
                % (incident_id, err)
            )

        self._incident_comment_cache[incident_id] = digests
        return digests


    def add_comment_to_incident(self, incident_id, comment):
        """
        Append a comment to an incident via the Microsoft Graph Security API
        sub-resource endpoint POST /incidents/{id}/comments. Each call posts
        exactly one alertComment; existing comments are preserved server-side.
        :param incident_id: Defender incident id
        :param comment: comment body
        :return: True on success, False otherwise
        """
        if not comment:
            return False
        try:
            request_url = f"{self.config.SECURITY_GRAPH_API}/incidents/{incident_id}/comments"
            request_data = {
                "@odata.type": "microsoft.graph.security.alertComment",
                "comment": comment,
            }
            response = self.retry_request(
                method="POST",
                url=request_url,
                data=dumps(request_data),
                headers=self.graph_headers,
            )
            if response.status_code not in (200, 204):
                self.log.error(
                    "Failed to update incident %s with comment - Error: %s"
                    % (incident_id, response.content)
                )
                return False
            self.log.info(f"Successfully added comment to incident {incident_id}")
            return True
        except Exception as err:
            self.log.error(
                "Failed to update incident %s with comment - Error: %s"
                % (incident_id, err)
            )
            return False


    def add_comment_to_alert(self, alert_id, comment):
        """
        Append a comment to an alert via the Microsoft Graph Security API
        sub-resource endpoint POST /security/alerts_v2/{id}/comments. Each
        call posts exactly one alertComment; existing comments are preserved
        server-side.
        :param alert_id: Defender alert id
        :param comment: comment body
        :return: void
        """
        if comment:
            try:
                request_data = {
                    "@odata.type": "microsoft.graph.security.alertComment",
                    "comment": comment,
                }
                request_url = (
                    self.config.SECURITY_GRAPH_API
                    + "/alerts_v2/%s/comments" % alert_id
                )
                response = self.retry_request(
                    method="POST",
                    url=request_url,
                    data=dumps(request_data),
                    headers=self.graph_headers,
                )

                # POST to the alerts_v2 comments sub-resource returns 201
                # Created on success; accept the same set the incident comment
                # path already accepts rather than 200 alone.
                if response.status_code not in (200, 201, 204):
                    self.log.error(
                        "Failed to update alert %s - Error: %s"
                        % (alert_id, response.content)
                    )
                else:
                    self.log.info(f"Successfully update alert {alert_id}")

            except Exception as err:
                self.log.error(
                    "Failed to update alert %s - Error: %s" % (alert_id, err)
                )

    def retry_request(
        self,
        method,
        url,
        retries=DEFENDER_API.DEFENDER_API_RETRY,
        backoff=DEFENDER_API.DEFENDER_API_TIMEOUT,
        param=None,
        headers=None,
        data=None,
        stream=None,
        auth=False
    ):
        """
        Retries the given API request in case of server errors or rate-limiting (HTTP 5xx or 429).

        :param method: HTTP method (GET, POST, etc.)
        :param url: URL to make the request to
        :param retries: Number of retry attempts
        :param backoff: backoff time in seconds
        :param headers: Headers to pass with the request
        :param param: Data to pass with the request (if applicable, e.g., for POST requests)
        :param data: Request body
        :param stream: Stream
        :param auth: Weather response from login api or from security api.
        :return: Response object from the request or None if it fails after retries
        """
        attempt = 0
        while attempt <= retries:
            try:
                response = requests.request(
                    method, url, params=param, headers=headers, data=data, stream=stream
                )
                response.raise_for_status()
                return response
            except requests.HTTPError as herr:
                if attempt < retries:
                    if response.status_code == AUTH_ERROR_STATUS_CODE:
                        self.authenticate_graph()
                        self.authenticate()
                        continue
                    if response.status_code in RETRY_STATUS_CODE:
                        self.log.warning(
                            f"Attempt {attempt + 1}: Server error or too many requests. Retrying..."
                        )
                        sleep(backoff // retries)
                        attempt += 1
                        continue
                    json_response = response.json()
                    if auth:
                        err_msg = f"{json_response.get('error')}: {json_response.get('error_description')}"
                    else:
                        err_msg = json_response.get("error", {}).get("message", "")
                    self.log.error(f"Error In Defender API calling: {err_msg}")
                    raise Exception(
                        "An error occurred during MicrosoftDefender Retry Request"
                    ) from herr
                self.log.error(f"Request failed after {retries} retries. Error: {herr}")
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from herr
            except requests.ConnectionError as cerr:
                if attempt < retries:
                    self.log.warning(
                        f"Attempt {attempt + 1}: Request Connection error or too many requests. Retrying..."
                    )
                    sleep(backoff // retries)
                    attempt += 1
                    continue
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from cerr
            except Exception as err:
                raise Exception(
                    "An error occurred during MicrosoftDefender Retry Request"
                ) from err
        raise Exception("Failed to complete microsoft request after multiple retries.")



