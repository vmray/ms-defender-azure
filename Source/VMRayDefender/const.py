"""
constant File
"""
# pylint: disable=invalid-name

from collections import namedtuple
from os import environ
from json import loads
from enum import Enum
from dataclasses import dataclass, field


def str_to_bool(value: str) -> bool:
    """
    Convert string to bool type
    """
    return loads(value.strip().lower()) if isinstance(value, str) else bool(value)


AlertConfig = namedtuple(
    "AlertConfig",
    [
        "SEVERITIES",
        "STATUSES",
        "EVIDENCE_ENTITY_TYPES",
        "MAX_ALERT_COUNT",
        "WINDOWS_DEFENDER_ATP",
        "WINDOWS_DEFENDER_AV",
        "SELECTED_DETECTION_SOURCES",
    ],
)

MachineActionConfig = namedtuple(
    "MachineActionConfig",
    ["JOB_TIMEOUT", "JOB_SLEEP", "MACHINE_TIMEOUT", "MACHINE_RETRY", "SLEEP"],
)

IndicatorConfig = namedtuple(
    "IndicatorConfig",
    [
        "ACTIVE",
        "ACTION",
        "INDICATOR_ALERT",
        "TITLE",
        "DESCRIPTION",
        "MAX_TI_INDICATORS_PER_REQUEST",
    ],
)


@dataclass
class GeneralConfig:
    """
    GeneralConfig
    """
    INDICATOR_VERDICTS: list[str]
    SELECTED_VERDICTS: list[str] = field(
        default_factory=lambda: ["suspicious", "malicious", "clean"]
    )


GENERAL_CONFIG = GeneralConfig(
    INDICATOR_VERDICTS=[
        verdict.lower()
        for verdict in environ.get(
            "VmraySampleVerdict", "Malicious & Suspicious"
        ).split(" & ")
    ],
)


@dataclass
class VMRayConfig:
    """
    VMRay Configuration
    """
    API_KEY: str
    URL: str
    ANALYSIS_JOB_TIMEOUT: int
    RESUBMIT: bool
    VMRay_API_RETRIES: int
    VMRay_API_TIMEOUT: int
    CONNECTOR_NAME: str = "MicrosoftDefenderForEndpointConnectorAzureFunction-Beta"
    API_KEY_TYPE: str = "REPORT"
    SSL_VERIFY: bool = True
    SUBMISSION_COMMENT: str = (
        "Sample from VMRay Analyzer - Microsoft Defender for Endpoint Connector"
    )
    SUBMISSION_TAGS: list[str] = field(
        default_factory=lambda: ["MicrosoftDefenderForEndpoint"]
    )
    AV_SUBMISSION_TAGS: list[str] = field(
        default_factory=lambda: [
            "MicrosoftDefenderForEndpoint",
            "SubmittedFromEndpoint",
        ]
    )
    ANALYSIS_TIMEOUT: int = 120
    RESUBMISSION_VERDICTS: list[str] = field(
        default_factory=lambda: ["malicious", "suspicious", "clean"]
    )


VMRay_CONFIG = VMRayConfig(
    API_KEY=environ.get("VmrayAPIKey"),
    URL=environ.get("VmrayBaseURL"),
    ANALYSIS_JOB_TIMEOUT=int(environ.get("VmrayAnalysisJobTimeout", 5)) * 60,
    RESUBMIT=str_to_bool(environ.get("VmrayResubmit", "True")),
    VMRay_API_RETRIES=int(environ.get("VmrayApiMaxRetry", 5)),
    VMRay_API_TIMEOUT=int(environ.get("VmrayAPIRetryTimeout", 5)) * 60,
)


@dataclass
class MachineActionStatus:
    """
    Machine Status
    """
    PENDING: str = "Pending"
    IN_PROGRESS: str = "InProgress"
    SUCCEEDED: str = "Succeeded"
    FAILED: str = "Failed"
    TIMEOUT: str = "TimeOut"
    CANCELLED: str = "Cancelled"
    AVAILABLE: list[str] = field(
        default_factory=lambda: ["Succeeded", "Failed", "TimeOut", "Cancelled"]
    )
    NOT_AVAILABLE: list[str] = field(default_factory=lambda: ["Pending", "InProgress"])
    FAIL: list[str] = field(default_factory=lambda: ["Cancelled", "TimeOut", "Failed"])


MACHINE_ACTION_STATUS = MachineActionStatus()


@dataclass
class APIConfig:
    """
    Microsoft API Configurations
    """
    TENANT_ID: str
    APPLICATION_ID: str
    APPLICATION_SECRET: str
    CONNECTION_STRING: str
    ACCOUNT_KEY: str
    ACCOUNT_NAME: str
    DEFENDER_API_TIMEOUT: int
    DEFENDER_API_RETRY: int
    AUTH_URL: str
    APPLICATION_NAME: str = "VMRayDefenderFoEndpointConnectorApp"
    RESOURCE_APPLICATION_ID_URI: str = "https://api.securitycenter.microsoft.com"
    URL: str = "https://api.securitycenter.microsoft.com"
    USER_AGENT: str = "MdePartner-VMRay-VMRayAnalyzer-AzureFunctionApp/4.4.1"
    CONTAINER_NAME: str = "vmray-defender-quarantine-files"
    ALERT_STATUS_CONTAINER_NAME: str = "vmray-defender-functionapp-status"


DEFENDER_API = APIConfig(
    TENANT_ID=environ.get("AzureTenantID", ""),
    APPLICATION_ID=environ.get("AzureClientID", ""),
    APPLICATION_SECRET=environ.get("AzureClientSecret", ""),
    CONNECTION_STRING=environ.get("AzureStorageConnectionString", ""),
    ACCOUNT_KEY=environ.get("AzureStorageAccountKey", ""),
    ACCOUNT_NAME=environ.get("StorageAccount", ""),
    DEFENDER_API_TIMEOUT=int(environ.get("DefenderApiRetryTimeout", 5)) * 60,
    DEFENDER_API_RETRY=int(environ.get("DefenderApiMaxRetry", 5)),
    AUTH_URL=f"https://login.microsoftonline.com/{environ.get('AzureTenantID', '')}/oauth2/token",
)


ALERT = AlertConfig(
    SEVERITIES=["Unspecified", "Informational", "Low", "Medium", "High"],
    STATUSES=["Unknown", "New", "InProgress", "Resolved"],
    EVIDENCE_ENTITY_TYPES=["File"],
    MAX_ALERT_COUNT=10000,
    WINDOWS_DEFENDER_ATP="WindowsDefenderAtp",
    WINDOWS_DEFENDER_AV="WindowsDefenderAv",
    SELECTED_DETECTION_SOURCES=["WindowsDefenderAtp", "WindowsDefenderAv"],
)

MACHINE_ACTION = MachineActionConfig(
    JOB_TIMEOUT=600,
    JOB_SLEEP=30,
    MACHINE_TIMEOUT=int(environ.get("MachineAvailabilityTimeout", 5)) * 60,
    MACHINE_RETRY=int(environ.get("MachineAvailabilityRetry", 10)),
    SLEEP=int(environ.get("MachineAvailabilityTimeout", 5))
    * 60
    // int(environ.get("MachineAvailabilityRetry", 10)),
)

INDICATOR = IndicatorConfig(
    ACTIVE=str_to_bool(environ.get("CreateIndicatorsInDefender", "True")),
    ACTION=environ.get("DefenderIndicatorAction"),
    INDICATOR_ALERT=str_to_bool(environ.get("DefenderIndicatorAlert", "False")),
    TITLE="Indicator based on VMRay Analyzer Report",
    DESCRIPTION="Indicator based on VMRay Analyzer Report",
    MAX_TI_INDICATORS_PER_REQUEST=500,
)


class EnrichmentSectionTypes(Enum):
    """
    VMRay section to enrich
    """
    CLASSIFICATIONS = "classifications"
    THREAT_NAMES = "threat_names"
    VTIS = "vtis"


class IngestionConfig(Enum):
    """
    Type of alert ingestion
    """
    EDR_BASED_INGESTION = True
    AV_BASED_INGESTION = True


class EDREnrichment(Enum):
    """
    EDR alert ingestion
    """
    ACTIVE = True
    SELECTED_SECTIONS = ["classiIngestionConfigfications", "threat_names", "vtis"]


class AVEnrichment(Enum):
    """
    Antivirus alert ingestion
    """
    ACTIVE = True
    SELECTED_SECTIONS = ["classifications", "threat_names", "vtis"]


class JobStatus(Enum):
    """
    Job Status
    """
    QUEUED = "queued"
    INWORK = "inwork"


HELPER_SCRIPT_FILE_NAME = "SubmitEvidencesToVMRay.ps1"

IOC_FIELD_MAPPINGS = {
    "ipv4": ["IpAddress"],
    "sha256": ["FileSha256"],
    "domain": ["DomainName"],
    "sha1": ["FileSha1"],
    "md5": ["FileMd5"],
}

MS_DEFENDER_SEVERITY_MAPPING = {
    "malicious": "High",
    "suspicious": "Medium",
    "clean": "Informational",
}

RETRY_STATUS_CODE = [500, 501, 502, 503, 504, 429]
AUTH_ERROR_STATUS_CODE = 401
