"""
VMRay API
"""
# pylint: disable=invalid-name

from datetime import datetime
from io import BytesIO
from ipaddress import ip_address
from time import sleep
from urllib.parse import urlparse

from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError

from ..const import GENERAL_CONFIG, JobStatus, RETRY_STATUS_CODE, VMRay_CONFIG


class VMRay:
    """
    Wrapper class for VMRayRESTAPI modules and functions.
    Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log):
        """
        Initialize, authenticate and healthcheck the VMRay instance,
        use VMRayConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = VMRay_CONFIG

        self.authenticate()
        self.healthcheck()

    def healthcheck(self):
        """
        Healtcheck for VMRay REST API, uses system_info endpoint
        :raise: When healtcheck error occured during the connection wih REST API
        :return: boolean status of VMRay REST API
        """
        method = "GET"
        url = "/rest/system_info"

        try:
            self.retry_request(method, url)
            self.log.info("VMRAY Healthcheck is successfull.")
            return True
        except Exception as err:
            self.log.error("Healthcheck failed. Error: %s" % (err))
            raise

    def authenticate(self):
        """
        Authenticate the VMRay REST API
        :raise: When API Key is not properly configured
        :return: void
        """
        try:
            self.api = VMRayRESTAPI(
                self.config.URL,
                self.config.API_KEY,
                self.config.SSL_VERIFY,
                self.config.CONNECTOR_NAME,
            )
            self.log.info(
                "Successfully authenticated the VMRay %s API" % self.config.API_KEY_TYPE
            )
        except Exception as err:
            self.log.error(err)
            raise

    def get_sample(self, identifier, sample_id=False):
        """
        Retrieve sample summary from VMRay database with sample_id or sha256 hash value
        :param identifier: sample_id or sha256 hash value to identify submitted sample
        :param sample_id: boolean value to determine which value (sample_id or sha256) is passed to function
        :return: dict object which contains summary data about sample
        """
        method = "GET"
        if sample_id:
            url = "/rest/sample/" + str(identifier)
        else:
            url = "/rest/sample/sha256/" + identifier

        try:
            response = self.retry_request(method, url)
            if response:
                if len(response) == 0:
                    self.log.info(
                        "Sample %s couldn't find in VMRay database." % (identifier)
                    )
                    return None
                self.log.info("Sample %s retrieved from VMRay" % identifier)
                return response
            return None
        except Exception as err:
            self.log.error(
                "Sample %s couldn't find in VMRay database. Error: %s"
                % (identifier, err)
            )
            return None

    def get_sample_iocs(self, sample_id):
        """
        Retrieve IOC values from VMRay
        :param sample_data: dict object which contains summary data about the sample
        :return iocs: dict object which contains IOC values according to the verdict
        """

        method = "GET"
        url = "/rest/sample/%s/iocs/verdict/%s"

        iocs = {}

        for key in GENERAL_CONFIG.INDICATOR_VERDICTS:
            try:
                response = self.retry_request(method, url % (sample_id, key))
                if response:
                    iocs[key] = response
                    self.log.info("IOC reports for %s retrieved from VMRay" % sample_id)
            except Exception as err:
                self.log.error(err)
        return iocs

    def get_child_samples(self, sample_data):
        """
        Retrieve all child sample ids
        :param sample_data: dict object which contains summary data about the sample
        :return child_samples: dict object containing all child sample ids
        """
        sample_id = sample_data["sample_id"]

        method = "GET"
        url = "/rest/sample/%s"

        child_samples = [sample_id]

        try:
            response = self.retry_request(method, url % sample_id)
            if response:
                child_sample_ids = response.get("sample_child_sample_ids", [])

                all_child_samples = set(child_sample_ids)

                for child_id in child_sample_ids:
                    all_child_samples.update(
                        self.get_child_samples({"sample_id": child_id})
                    )

                child_samples.extend(list(all_child_samples))
                self.log.info("Child samples for %s retrieved from VMRay" % sample_id)
        except Exception as err:
            self.log.error(err)

        return child_samples

    def get_sample_vtis(self, sample_id):
        """
        Retrieve VTI's (VMRay Threat Identifier) values about the sample
        :param sample_id: id value of the sample
        :return: dict object which contains VTI information about the sample
        """
        method = "GET"
        url = "/rest/sample/%s/vtis" % str(sample_id)

        try:
            response = self.retry_request(method, url)
            self.log.info(
                "Sample %s VTI's successfully retrieved from VMRay" % sample_id
            )
            return response
        except Exception as err:
            self.log.info(
                "Sample %s VTI's couldn't retrieved from VMRay database. Error: %s"
                % (sample_id, err)
            )
            return None

    def get_submission_analyses(self, submission_id):
        """
        Retrieve analyses details of submission to detect errors
        :param submission_id: id value of the submission
        :return: dict object which contains analysis information about the submission
        """
        method = "GET"
        url = "/rest/analysis/submission/%s" % str(submission_id)
        try:
            response = self.retry_request(method, url)
            self.log.info(
                "Submission %s analyses successfully retrieved from VMRay"
                % submission_id
            )
            return response
        except Exception as err:
            self.log.info(
                "Submission %s analyses couldn't retrieved from VMRay. Error: %s"
                % (submission_id, err)
            )
            return None

    def parse_sample_data(self, sample):
        """
        Parse and extract summary data about the sample with keys below
        :param sample: dict object which contains raw data about the sample
        :return sample_data: dict objects which contains parsed data about the sample
        """
        sample_data = {}
        keys = [
            "sample_id",
            "sample_verdict",
            "sample_vti_score",
            "sample_severity",
            "sample_child_sample_ids",
            "sample_parent_sample_ids",
            "sample_md5hash",
            "sample_sha256hash",
            "sample_webif_url",
            "sample_classifications",
            "sample_threat_names",
            "sample_filename",
        ]
        if sample is not None:
            if isinstance(sample, list):
                sample = sample[0]
            for key in keys:
                if key in sample:
                    sample_data[key] = sample[key]
        return sample_data

    def parse_sample_vtis(self, vtis):
        """
        Parse and extract VTI details about the sample with keys below
        :param vtis: dict object which contains raw VTI data about the sample
        :return parsed_vtis: dict object which contains parsed VTI data about the sample
        """
        parsed_vtis = []

        if vtis is not None:
            for vti in vtis["threat_indicators"]:
                parsed_vtis.append(
                    {
                        "category": vti["category"],
                        "classifications": vti["classifications"],
                        "operation": vti["operation"],
                    }
                )
        return parsed_vtis

    def parse_sample_iocs(self, iocs):
        """
        Parse and extract process, file and network IOC values about the sample
        :param iocs: dict object which contains raw IOC data about the sample
        :return ioc_data: dict object which contains parsed/extracted process, file and network IOC values
        """
        file_iocs = self.parse_file_iocs(iocs)
        network_iocs = self.parse_network_iocs(iocs)
        return {**file_iocs, **network_iocs}

    def parse_file_iocs(self, iocs):
        """
        Parse and extract File IOC values (sha256, file_name) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return file_iocs: dict object which contains sha256 hashes and file_names as IOC values
        """
        file_iocs = {"sha256": set(), "sha1": set(), "md5": set()}

        for ioc_type in iocs:
            files = iocs[ioc_type]["iocs"]["files"]
            for file in files:
                if file["verdict"] in GENERAL_CONFIG.INDICATOR_VERDICTS:
                    for file_hash in file["hashes"]:
                        file_iocs["sha256"].add(
                            (file_hash["sha256_hash"], file["verdict"])
                        )
                        file_iocs["sha1"].add((file_hash["sha1_hash"], file["verdict"]))
                        file_iocs["md5"].add((file_hash["md5_hash"], file["verdict"]))

        return file_iocs

    def parse_network_iocs(self, iocs):
        """
        Parse and extract Network IOC values (domain, IPV4) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return network_iocs: dict object which contains domains and IPV4 addresses as IOC values
        """
        network_iocs = {"domain": set(), "ipv4": set()}

        for ioc_type in iocs:
            ips = iocs[ioc_type]["iocs"]["ips"]
            for ip in ips:
                for domain in ip["domains"]:
                    network_iocs["domain"].add((domain, ip["verdict"]))
                network_iocs["ipv4"].add((ip["ip_address"], ip["verdict"]))

            urls = iocs[ioc_type]["iocs"]["urls"]
            for url in urls:
                for original_url in url["original_urls"]:
                    parsed_netloc = urlparse(original_url).netloc
                    try:
                        ip_address(parsed_netloc)
                        network_iocs["ipv4"].add(
                            (parsed_netloc, url.get("verdict", "unknown"))
                        )
                    except ValueError:
                        network_iocs["domain"].add(
                            (parsed_netloc, url.get("verdict", "unknown"))
                        )

        return network_iocs

    def submit_samples(self, evidences):
        """
        Submit sample to VMRay Sandbox to analyze
        :param evidences: list of evidences which downloaded from Microsoft Defender for Endpoint
        :return submissions: dict object which contains submission_id and sample_id
        """
        method = "POST"
        url = "/rest/sample/submit"

        params = {
            "comment": self.config.SUBMISSION_COMMENT,
            "tags": ",".join(self.config.SUBMISSION_TAGS),
            "user_config": """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT,
        }

        submissions = []

        for evidence in evidences:
            try:
                file_obj = BytesIO(evidence.download_file_path)
                file_obj.name = evidence.file_name
                params["sample_file"] = file_obj
                try:
                    response = self.retry_request(method, url, param=params)
                except Exception as err:
                    self.log.error(err)

                if response:
                    if len(response["errors"]) == 0:
                        submission_id = response["submissions"][0]["submission_id"]
                        sample_id = response["samples"][0]["sample_id"]
                        submissions.append(
                            {
                                "submission_id": submission_id,
                                "sample_id": sample_id,
                                "sha256": evidence.sha256,
                                "evidence": evidence,
                            }
                        )
                        self.log.debug("File %s submitted to VMRay" % file_obj.name)
                    else:
                        for error in response["errors"]:
                            self.log.error(str(error))
            except Exception as err:
                self.log.error(err)

        self.log.info("%d files submitted to VMRay" % len(submissions))
        return submissions

    def wait_submissions(self, submissions, timeout_status):
        """
        Wait for the submission analyses to finish
        :param submissions: list of submission dictionaries
        :return custom_dict : contains submission status, submission info and API response
        """

        method = "GET"
        url = "/rest/submission/%s"
        submission_objects = [
            {
                "submission_id": submission["submission_id"],
                "evidence": submission["evidence"],
                "sha256": submission["sha256"],
                "sample_id": submission["sample_id"],
                "timestamp": None,
                "error_count": 0,
            }
            for submission in submissions
        ]

        self.log.info("Waiting %d submission jobs to finish" % len(submission_objects))
        while len(submission_objects) > 0:
            sleep(VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT / 60)
            for submission_object in submission_objects:
                try:
                    response = self.retry_request(
                        method, url % submission_object["submission_id"]
                    )

                    if response:
                        if response["submission_finished"]:
                            submission_objects.remove(submission_object)
                            self.log.info(
                                "Submission job %s finished"
                                % submission_object["submission_id"]
                            )
                            yield {
                                "finished": True,
                                "response": response,
                                "submission": submission_object,
                            }
                        elif submission_object["timestamp"] is None:
                            if self.is_submission_started(
                                submission_object["submission_id"]
                            ):
                                submission_object["timestamp"] = datetime.now()
                        elif (
                            datetime.now() - submission_object["timestamp"]
                        ).seconds >= VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT:
                            submission_objects.remove(submission_object)
                            self.log.error(
                                "Submission job %d exceeded the configured time threshold."
                                % submission_object["submission_id"]
                            )
                            timeout_status.vmray_timeout.append(
                                {
                                    "submission_id": submission_object["submission_id"],
                                    "timeout": True,
                                }
                            )
                            yield {
                                "finished": False,
                                "response": response,
                                "submission": submission_object,
                            }
                    else:
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }

                except Exception as err:
                    self.log.error(str(err))
                    if submission_object["error_count"] >= 5:
                        yield {
                            "finished": False,
                            "response": None,
                            "submission": submission_object,
                        }
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")

    def is_submission_started(self, submission_id):
        """
        Check if submission jobs are started
        :param submission_id: id value of submission
        :return status: boolean value of status
        """

        method = "GET"
        url = "/rest/job/submission/%d"

        try:
            response = self.retry_request(method, url % submission_id)
            self.log.info(
                "Submission %d jobs successfully retrieved from VMRay" % submission_id
            )
            if response:
                for job in response:
                    if job["job_status"] == JobStatus.INWORK.value:
                        self.log.info(
                            "At least one job is started for submission %d"
                            % submission_id
                        )
                        return True
                self.log.info(
                    "No job has yet started for submission %d" % submission_id
                )
                return False
            return False
        except Exception as err:
            self.log.info(
                "Submission %d jobs couldn't retrieved from VMRay. Error: %s"
                % (submission_id, err)
            )
            return False

    def check_submission_error(self, submission):
        """
        Check and log any analysis error in finished submissions
        :param submission: list of submission_id's
        :return: void
        """
        analyses = self.get_submission_analyses(submission["submission_id"])
        if analyses is not None:
            for analysis in analyses:
                if analysis["analysis_severity"] == "error":
                    self.log.error(
                        "Analysis %d for submission %d has error: %s"
                        % (
                            analysis["analysis_id"],
                            submission["submission_id"],
                            analysis["analysis_result_str"],
                        )
                    )

    def get_sample_submissions(self, sample):
        sample_id = sample["sample_id"]

        method = "GET"
        url = "/rest/submission/sample/%s" % sample_id

        try:
            response = self.retry_request(method, url)
            if response:
                if len(response) == 0:
                    self.log.info(
                        "Sample %s couldn't find in VMRay database." % (sample_id)
                    )
                    return None
                self.log.info("Sample %s retrieved from VMRay" % sample_id)
                return response
            return response
        except Exception as err:
            self.log.error("Error: %s" % err)
            return None

    def get_av_submissions(self, machine, submissions):
        if len(machine.av_evidences) > 0:
            if machine.run_script_live_response_finished:
                for evidence in machine.av_evidences.keys():
                    for submission in submissions:
                        # if submission["sha256"] == evidence:
                        submission["evidence"] = machine.av_evidences[evidence]
        return submissions

    def submit_av_samples(self, file_objects):
        """
        Submit AV files to VMRay
        :param file_objects: Blob from azure
        :return: Submissions List
        """
        params = {
            "comment": self.config.SUBMISSION_COMMENT,
            "tags": ",".join(self.config.AV_SUBMISSION_TAGS),
            "user_config": """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT,
        }
        method = "POST"
        url = "/rest/sample/submit"
        submissions = []
        for file_obj in file_objects:
            try:
                for hash_val, file in file_obj.items():
                    params["sample_file"] = file
                    response = self.retry_request(method, url, param=params)
                    if response:
                        if len(response["errors"]) == 0:
                            submission_id = response["submissions"][0]["submission_id"]
                            sample_id = response["samples"][0]["sample_id"]
                            submissions.append(
                                {
                                    "submission_id": submission_id,
                                    "sample_id": sample_id,
                                    "sha256": hash_val,
                                }
                            )
                            self.log.info(
                                f"Submission ID {submission_id} and Sample ID {sample_id}"
                            )
                        else:
                            for error in response["errors"]:
                                self.log.error(str(error))
            except Exception as err:
                self.log.error(err)

        self.log.info("%d files submitted to VMRay" % len(submissions))
        return submissions

    def wait_av_submissions(self, submissions):
        """
        Wait for the submission analyses to finish
        :param submissions: list of submission dictionaries
        :return custom_dict : contains submission status, submission info and API response
        """

        method = "GET"
        url = "/rest/submission/%s"
        submission_objects = [
            {
                "submission_id": submission["submission_id"],
                "evidence": submission["evidence"],
                "sha256": submission["sha256"],
                "sample_id": submission["sample_id"],
                "timestamp": None,
                "error_count": 0,
            }
            for submission in submissions
        ]

        self.log.info("Waiting %d submission jobs to finish" % len(submission_objects))
        while len(submission_objects) > 0:
            sleep(VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT / 60)
            for submission_object in submission_objects:
                try:
                    response = self.api.call(
                        method, url % submission_object["submission_id"]
                    )
                    if response["submission_finished"]:
                        submission_objects.remove(submission_object)
                        self.log.info(
                            "Submission job %s finished"
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": True,
                            "response": response,
                            "submission": submission_object,
                        }
                    elif submission_object["timestamp"] is None:
                        if self.is_submission_started(
                            submission_object["submission_id"]
                        ):
                            submission_object["timestamp"] = datetime.now()
                    elif (
                        datetime.now() - submission_object["timestamp"]
                    ).seconds >= VMRay_CONFIG.ANALYSIS_JOB_TIMEOUT:
                        submission_objects.remove(submission_object)
                        self.log.error(
                            "Submission job %d exceeded the configured time threshold."
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }

                except Exception as err:
                    self.log.error(str(err))
                    if submission_object["error_count"] >= 5:
                        yield {
                            "finished": False,
                            "response": None,
                            "submission": submission_object,
                        }
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")

    def retry_request(
        self,
        method,
        url,
        vmray_retries=VMRay_CONFIG.VMRay_API_RETRIES,
        backoff=VMRay_CONFIG.VMRay_API_TIMEOUT,
        param=None,
    ):
        """
        Retries the given API request in case of server errors or rate-limiting (HTTP 5xx or 429).

        :param method: HTTP method (GET, POST, etc.)
        :param url: URL to make the request to
        :param vmray_retries: Number of retry attempts
        :param backoff: backoff time in seconds
        :param param: Data to pass with the request (if applicable, e.g., for POST requests)
        :return: Response object from the request or None if it fails after retries
        """
        attempt = 0
        while attempt <= vmray_retries:
            try:
                response = self.api.call(method, url, params=param)
                return response
            except VMRayRESTAPIError as err:
                if attempt < vmray_retries:
                    if err.status_code in RETRY_STATUS_CODE:
                        self.log.warning(
                            f"Attempt {attempt + 1}: Server error or too many requests. Retrying..."
                        )
                        sleep(backoff // vmray_retries)
                        attempt += 1
                        continue
                    self.log.error(f"Error In VMRay: {err.args}")
                    raise Exception("An error occurred during retry request") from err
                self.log.error(
                    f"Request failed after {vmray_retries} retries. Error: {err}"
                )
                raise Exception("An error occurred during retry request") from err
