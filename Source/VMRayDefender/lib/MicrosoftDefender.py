"""
Microsoft Defender Class
"""

from base64 import b64encode
from datetime import datetime, timedelta, timezone
from gzip import GzipFile
from io import BytesIO
from json import dumps
from os import path
from string import Template
from time import sleep

import requests
from azure.storage.blob import ContainerSasPermissions, generate_container_sas
from requests_toolbelt.multipart.encoder import MultipartEncoder

from ..const import (
    ALERT,
    DEFENDER_API,
    EnrichmentSectionTypes,
    INDICATOR,
    IOC_FIELD_MAPPINGS,
    MACHINE_ACTION,
    MACHINE_ACTION_STATUS,
    RETRY_STATUS_CODE,
    HELPER_SCRIPT_FILE_NAME,
    AUTH_ERROR_STATUS_CODE,
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
        self.config = DEFENDER_API
        self.log = log

        self.authenticate()

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
                method="POST", url=self.config.AUTH_URL, data=body
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

    def get_evidences(self, alert):
        """
        Retrieve alerts and related evidence information
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-alerts
        :exception: when alerts and evidences are not properly retrieved
        :return alerts: dict of alert objects
        """
        request_url = f"{self.config.URL}/api/alerts/{alert}"

        evidences = {}

        try:
            response = self.retry_request(
                method="GET", url=request_url, headers=self.headers
            )
            json_response = response.json()

            if not json_response:
                self.log.error(
                    "Failed to parse api response - Error: value key not found in dict."
                )
                return evidences

            if "error" in json_response:
                self.log.error(
                    "Failed to retrieve alerts - Error: %s"
                    % json_response["error"]["message"]
                )
                return evidences
            raw_alert = json_response
            self.log.info(f"Successfully retrieved alert {alert}")
            try:
                if raw_alert["detectionSource"] not  in ALERT.SELECTED_DETECTION_SOURCES:
                    return evidences
                for evidence in raw_alert["evidence"]:
                    evidence_sha256 = evidence["sha256"]

                    if not all([
                        evidence["entityType"] in ALERT.EVIDENCE_ENTITY_TYPES
                        and evidence_sha256 is not None
                        and evidence_sha256.lower() != "none"
                    ]):
                        continue

                    if evidence_sha256 in evidences:
                        evidences[evidence_sha256].alert_ids.add(
                            raw_alert["id"]
                        )
                        evidences[evidence_sha256].machine_ids.add(
                            raw_alert["machineId"]
                        )
                    else:
                        evidences[evidence_sha256] = Evidence(
                            sha256=evidence_sha256,
                            sha1=evidence["sha1"],
                            file_name=evidence["fileName"],
                            file_path=evidence["filePath"],
                            alert_id=raw_alert["id"],
                            machine_id=raw_alert["machineId"],
                            detection_source=raw_alert[
                                "detectionSource"
                            ],
                        )
                        evidences[evidence_sha256].set_comments(
                            raw_alert["comments"]
                        )
            except Exception as err:
                self.log.warning(
                    "Failed to parse alert object - Error: %s" % err
                )
            self.log.info(
                f"Successfully retrieved alert {alert} and {len(evidences)} evidences"
            )
        except Exception as err:
            self.log.error("Failed to retrieve alerts - Error: %s" % err)

        return evidences

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

    def wait_run_script_live_response(self, live_response_id, timeout_status):
        """
        This function checks the live response execution
        :param live_response_id: Live response ID
        :param timeout_status: Timeout status object
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
            timeout_status.live_response_timeout = False
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
                    timeout_status.live_response_status = False
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
            timeout_status.live_response_timeout = True
            has_error = True
            self.cancel_machine_action(live_response_id)
            sleep(MACHINE_ACTION.JOB_SLEEP)

        if has_error:
            return False, machine_action

        return True, machine_action

    def wait_live_response(self, live_response, machine_timeout):
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
            machine_timeout.live_response_timeout = False
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
            machine_timeout.live_response_timeout = True
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

    def run_edr_live_response(self, machines, timeout_status):
        """
        This function will execute EDR live response command
        :param machines: List of machine contains evidences
        :param timeout_status: Timeout status objects
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
                                                        evidence.live_response,
                                                        timeout_status,
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
                    timeout_status.machine_timeout = True
                    self.log.error(
                        "Machine %s was not available during the timeout (%s seconds)"
                        % (machine.id, MACHINE_ACTION.MACHINE_TIMEOUT)
                    )

        return machines

    def run_av_submission_script(self, machines, timeout_status, threat_name=""):
        """
        This function will execute AV live response command
        :param machines: List of machine contains evidences
        :param timeout_status: Timeout status objects
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
                                        live_response_id, timeout_status
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
                                                            if "NoMatchFound" in log_msg:
                                                                self.log.info(
                                                                    "The evidence hash does"
                                                                    " not match the hash of any quarantined files."
                                                                )
                                                            machine.run_script_live_response_finished = (
                                                                True
                                                            )
                                                        else:
                                                            if file_counter < 2:
                                                                file_counter += 1
                                                                self.log.info(
                                                                    f"No quarantined items for threat {threat_name} found waitng to get the file"
                                                                )
                                                                sleep(60)
                                                                continue
                                                            self.log.info(
                                                                "No Quartine Files Found"
                                                            )
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
                    else:
                        # waiting the machine for pending live response jobs
                        sleep(MACHINE_ACTION.SLEEP)
                        # increment timeout_counter to check timeout in While loop
                        machine.timeout_counter += 1

                if MACHINE_ACTION.MACHINE_RETRY <= machine.timeout_counter:
                    timeout_status.machine_timeout = True
                    self.log.error(
                        "Machine %s was not available during the timeout (%s seconds)"
                        % (machine.id, MACHINE_ACTION.MACHINE_TIMEOUT)
                    )
                if MACHINE_ACTION.MACHINE_RETRY <= live_response_counter:
                    self.log.error("Maximum number of live response retries exceeded")

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
        self, indicator_data, old_indicators, alert_id, hash_value
    ):
        """
        Create indicators objects based on VMRay Analyzer indicator data and retrieved indicators from Microsoft Defender for Endpoint
        :param indicator_data: dict of indicators which retrieved from VMRay submission
        :param old_indicators: set of indicators which retrieved from Microsoft Defender for Endpoint
        :param alert_id: Defender Alert ID
        :param hash: Sample Hash
        :return indicator_objects: list of indicator objects
        """

        indicator_objects = []
        for key in indicator_data:
            if key in IOC_FIELD_MAPPINGS.keys():
                for indicator_field in IOC_FIELD_MAPPINGS[key]:
                    indicator_value = indicator_data[key]

                    for indicator in indicator_value:
                        if indicator[0] not in old_indicators:
                            expiration_date = datetime.now(timezone.utc) + timedelta(
                                days=180
                            )
                            expiration_date = expiration_date.strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            )
                            indicator_objects.append(
                                Indicator(
                                    indicator_type=indicator_field,
                                    value=indicator[0],
                                    action=INDICATOR.ACTION,
                                    application=self.config.APPLICATION_NAME,
                                    title=INDICATOR.TITLE,
                                    description=f"{INDICATOR.DESCRIPTION}\nAlert ID: {alert_id}\n Generated By {hash_value}",
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

    def enrich_alerts(self, evidence, sample_data, sample_vtis, enrichment_sections):
        """
        Enrich alerts with VMRay Analyzer submission metadata
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
        :param evidence: evidence object
        :param sample_data: dict object which contains summary data about the sample
        :param sample_vtis: dict object which contains parsed VTI data about the sample
        :exception: when alert is not updated properly
        :return void:
        """
        comment = "Evidence SHA256:\n"
        comment += sample_data["sample_sha256hash"] + "\n\n"
        comment += (
            "VMRAY Analyzer Verdict: %s\n\n" % sample_data["sample_verdict"].upper()
        )
        comment += "Sample Url:\n"
        comment += sample_data["sample_webif_url"] + "\n\n"

        if EnrichmentSectionTypes.CLASSIFICATIONS.value in enrichment_sections:
            comment += "Classifications:\n"
            comment += "\n".join(sample_data["sample_classifications"]) + "\n\n"

        if EnrichmentSectionTypes.THREAT_NAMES.value in enrichment_sections:
            comment += "Threat Names:\n"
            comment += "\n".join(sample_data["sample_threat_names"]) + "\n\n"

        if EnrichmentSectionTypes.VTIS.value in enrichment_sections:
            comment += "VTI's:\n"
            comment += (
                "\n".join(list(set([vti["operation"] for vti in sample_vtis]))) + "\n\n"
            )

        if b64encode(comment.encode("utf-8")).decode("utf-8") not in evidence.comments:
            for alert_id in evidence.alert_ids:
                try:
                    request_data = {"comment": comment}
                    request_url = self.config.URL + "/api/alerts/%s" % alert_id
                    response = self.retry_request(
                        method="PATCH",
                        url=request_url,
                        data=dumps(request_data),
                        headers=self.headers,
                    )

                    if response.status_code != 200:
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
    ):
        """
        Retries the given API request in case of server errors or rate-limiting (HTTP 5xx or 429).

        :param method: HTTP method (GET, POST, etc.)
        :param url: URL to make the request to
        :param retries: Number of retry attempts
        :param backoff: backoff time in seconds
        :param headers: Headers to pass with the request
        :param param: Data to pass with the request (if applicable, e.g., for POST requests)
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
                        self.authenticate()
                        continue
                    if response.status_code in RETRY_STATUS_CODE:
                        self.log.warning(
                            f"Attempt {attempt + 1}: Server error or too many requests. Retrying..."
                        )
                        sleep(backoff // retries)
                        attempt += 1
                        continue
                    self.log.error(f"Error In Defender API calling: {herr}")
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

