# Microsoft Defender for Endpoint Azure Connector for VMRay Advanced Malware Sandbox

**Latest Version:** 1.0.0 - **Release Date:26/05/2026** 

## Overview

This project is an integration between Microsoft Defender for Endpoint and VMRay products: Analyzer, FinalVerdict and TotalInsight. 
The connector will collect alerts and related evidences, and query or submit these samples into VMRay Sandbox.
It accelerates the triage of alerts by adding comments to the alert in MS Defender Console with the analysis of the sample.
It also retrieves IOC values from VMRay and submits them into Microsoft Defender for Endpoint.

## Solution Overview
- The connector is built using Azure logic app, Azure functions app and Azure Storage.
  1. Azure Logic app `SubmitDefenderAlertsToVMRay` monitors the alerts from MS Defender as soon any AV/EDR alerts are generated. If any AV/EDR alert is found, it will send the alert details to the Azure function app `VMRayDefender`.
  2. Azure function app `VMRayDefender` checks if the alert contains a file and checks if the file hash has already been analyzed by VMRay.
  3. If the hash was already analysed, the system checks if user configure to reanalyse the hash in configuration step, if yes it resubmits that to VMRay to reanalyze, if not it skips re-examining it.
  4. Azure function app `VMRayDefender` requests the file from Microsoft Defender by starting a live response session.
  5. Microsoft Defender starts a live response session that run PowerShell code on the endpoint. The PowerShell moves the files out of quarantine to a temporary folder before sending to Azure storage(vmray-defender-quarantine-files) container. 
  6. Azure function app `VMRayDefender` monitors the Azure storage(vmray-defender-quarantine-files) container and submits the quarantine file to VMRay.
  7. Azure function app `VMRayDefender` will wait till the submission is completed and When the VMRay analysis is done VMRay results are sent back to the Azure function app `VMRayDefender`.
  8. The Azure function app `VMRayDefender` post the results as a note within the relevant defender alert.
  9. If configured to send IOCs, the Azure function app `VMRayDefender` provides the IOCs as the indicators to Microsoft Defender that may use them for automatically alerting or blocking.
   
**Important**: This solution can only analyze files quarantined by Defender Antivirus or flagged by Defender EDR. It cannot access files that were removed or blocked outright.
On the endpoint, Windows Security > Protection History shows if a threat was blocked (removed or restricted) or quarantined.

To improve alert enrichment, set the remediation action to "Quarantine: Moves files to quarantine" for all threat levels via Intune or Group Policy.
Note: Some threats may still be blocked by other mechanisms (e.g., EDR in block mode, active threat blocking).

![solution_overview](Images/solution_overview.png)

## Requirements
- Microsoft Defender for Endpoint.
- VMRay Analyzer, VMRay FinalVerdict, VMRay TotalInsight.
- Microsoft Azure
  1. Azure functions with Flex Consumption plan.
     Reference: https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-plan
	 **Note: Flex Consumption plans are not available in all regions, please check if the region your are deploying the function is supported, if not we suggest you to deploy the function app with premium plan. **
	 Reference: https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-how-to?tabs=azure-cli%2Cvs-code-publish&pivots=programming-language-python#view-currently-supported-regions
  2. Azure functions Premium plan.
	 Reference: https://learn.microsoft.com/en-us/azure/azure-functions/functions-premium-plan
  3. Azure Logic App with Consumption plan.
     Reference: https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-pricing#consumption-multitenant
  4. Azure storage with Standard general-purpose v2.

## VMRay Configurations

- In VMRay Console, you must create a Connector API key by following the steps below:
  
  1. Create a user dedicated to this API key (to avoid that the API key is deleted if an employee leaves)
  2. Create a role that allows to "View shared submission, analysis and sample" and "Submit sample, manage own jobs, reanalyse old analyses and regenerate analysis reports".
  3. Assign this role to the created user
  4. Login as this user and create an API key by opening Settings > Analysis > API Keys.
  5. Please save the keys, which will be used in configuring the Azure Function.

     
## Microsoft Defender for Endpoint Configurations

### Creating Application for API Access

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Microsoft Entra ID` service.

![01](Images/01.png)

- Click `Add->App registration`.

![02](Images/02.png)

- Enter the name of application, select supported account types, and click on `Register`.

![03](Images/03.png)

- In the application overview you can see `Application Name`, `Application ID` and `Tenant ID`.

![04](Images/04.png)

- After creating the application, we need to set API permissions for connector. For this purpose,
  - Click `Manage->API permissions` tab
  - Click `Add a permission` button
  - Select `APIs my organization uses`
  - Search `WindowsDefenderATP` and click the search result

![05](Images/05.png)

- On the next page, select `Application Permissions` and check the permissions according to the table below. Then, click `Add permissions` button below.

|       Category       |   Permission Name   | Description                                                            |
|:---------------------|:--------------------|:-----------------------------------------------------------------------|
| Alert                | Alert.Read.All      | Needed to retrieve alerts and related evidence                         |
| Alert                | Alert.ReadWrite.All | Needed to enrich alerts with sample information                        |
| Machine              | Machine.LiveResponse | Needed to gather evidences from machines                               |
| Machine              | Machine.Read.All | Needed to retrieve information about machines                          |
| Ti                   | Ti.Read.All | Needed to retrieve indicators                                          |
| Ti                   | Ti.ReadWrite | Needed to retrieve and submit indicators (application specific)        |
| Ti                   | Ti.ReadWrite.All | Needed to retrieve and submit indicators (general)                     |
| Library              | Library.Manage | Needed to upload custom ps1 script for retrieving AV related evidences |

![06](Images/06.png)

- After setting only the necessary permissions, click the `Grant admin consent for ...` button to approve permissions.

![07](Images/07.png)

- We need secrets to access programmatically. For creating secrets
  - Click `Manage->Certificates & secrets` tab
  - Click `Client secrets` tab
  - Click `New client secret` button
  - Enter description and set expiration date for secret

![08](Images/08.png)

- Use Secret `Value` and `Secret ID` to configure connector.

![09](Images/09.png)

**Reference**
- [https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world)


### Activating Live Response and Automated Investigation

- Open [https://security.microsoft.com](https://security.microsoft.com)
- Open `Settings` page and `Endpoints` tab.
- Open `Advanced features`.
- Activate `Live Response`,  `Live Response for Servers` and `Live Response unsigned script execution` options.

![Activating Live Response](Images/10.PNG)

## Microsoft Azure Function App Installation And Configuration

### Deployment of Function App 

#### Flex Consumption Plan

- Click on below button to deploy:

  [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fvmray%2Fms-defender-azure%2Frefs%2Fheads%2Fmain%2FFunctionApp%2FFlexConsumptionPlan%2Fazuredeploy.json)

#### Premium Plan

- Click on below button to deploy:

  [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fvmray%2Fms-defender-azure%2Frefs%2Fheads%2Fmain%2FFunctionApp%2FPremiumPlan%2Fazuredeploy.json)
  
  

- On the next page, please provide the values accordingly.
  
![13a](Images/13a.png)

|       Fields       | Description                                                                                        |
|:---------------------|:---------------------------------------------------------------------------------------------------
| Subscription		| Select the appropriate Azure Subscription                                                          | 
| Resource Group 	| Select the appropriate Resource Group                                                              |
| Region			| Based on Resource Group this will be auto populated                                                |
| Function Name		| Please provide a function name if needed to change the default value                               |
| Azure Client ID   | Enter the Azure Client ID created in the App Registration Step                                     |
| Azure Client Secret | Enter the Azure Client Secret created in the App Registration Step                                 |
|Azure Tenant ID | Enter the Azure Tenant ID of the App Registration                                                  |
| Azure Storage Connection String| Please leave this empty                                                                            |
| Azure Storage Account Key| Please leave this empty                                                                            |
| App Insights Workspace Resource ID | Go to `Log Analytics workspace` -> `Settings` -> `Properties`, Copy `Resource ID` and paste here   |
| Vmray Base URL | VMRay Base URL                                                                                     |
| Vmray API Key | VMRay API Key                                                                                      |
| Vmray Resubmit | If true, the files will be resubmitted to VMRay analyser, even if the file hash was found in VMRay |
| Vmray API Retry Timeout | Provide maximum time to wait in minutes, when VMRay API is not responding                          |
| Vmray API Max Retry | Provide number of retries, when VMRay API is not responding                                        |
| Vmray Analysis Job Timeout | Provide maximum time to wait in minutes, when VMRay Job submissions is not responding              |
| Defender API Retry Timeout | Provide maximum time to wait in minutes, when Microsoft Defender API is not responding.            |
| Defender API Max Retry | Provide number of retries, when Microsoft Defender API is not responding                           |
| Machine Availability Timeout | Provide maximum time to wait in minutes, when the machine is not responding                        |
| Machine Availability Retry | Provide number of retries, when machine is not responding                                          |
| Create Indicators In Defender | If true, Indicators will be created in Microsoft Defender                                          |
| Vmray Sample Verdict | Based on the selection, Indicators will be created in Microsoft Defender                           |
| Defender Indicator Action | The action that is taken if the indicator is discovered in the organization                        |
| Defender Indicator Alert | True if alert generation is required, False if this indicator shouldn't generate an alert          |
	
- Once you provide the above values, please click on `Review + create` button.

### Storage Account Keys

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Storage accounts` service.

![14](Images/14.png)

- Open the storage account, the name starts with `vmraystorage`.

- Go to `Security + networking` -> `Access keys`, Copy `Connection string` and save it temporarily for next steps.

![16](Images/16.png)

- Go to `Security + networking` -> `Access keys`, Copy `Key` and save it temporarily for next steps.

![17](Images/17.png)


### Configuration of Function App

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Function App` service.

![19](Images/19.png)

- Open the VMRay FunctionApp name starts with `vmraydefender`.
- Go to `Settings`->`Environment variables`, double-click `AzureStorageConnectionString` and provide the `connection string` value copied in the previous step and click on `save`.
- Go to `Settings`->`Environment variables`, double-click `AzureStorageAccountKey` and provide the `Key` value copied in the previous step and click on `save`.
- Click on `Apply` -> `Confirm` buttons.

![20](Images/20.png)

- Go to `Overview` -> click on `Restart`.

![21](Images/21.png)

## Microsoft Azure Logic App Installation And Configuration

### Submit-Defender-Alerts-To-VMRay Logic App Installation

- This playbook is mandatory. The Logic App collects the Defender Alerts and sends to VMRay Function App Connector for further processing.

- Click on below button to deploy:

  [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fvmray%2Fms-defender-azure%2Frefs%2Fheads%2Fmain%2FLogicApp%2Fazuredeploy1.json)

- On the next page, provide the appropriate `Subscription` and `Resource group` and click on `Review & create`.

  **Note**: When deploying the function app if you chose a different name, please kindly provide the same name here as well.
  
  
![22](Images/22.png)

- Once the deployment is complete, go to newly deployed logic app, click on edit. The logic app will open in a designer mode.

- Click on the `WDATP Trigger`, click on `Add new`.

![23](Images/23.png)

- On the next page, choose `Authentication` as `Service principal`, and provide the `ClientId`, `Client Secret` and `Tenant` values created via Entra ID app registration previously.

![24](Images/24.png)
![25](Images/25.png)

- Click on `Alerts - Get single Alert` action, click on `Change connection` and select the connection created above.

![24a](Images/24a.png)

#### Filtering the Defender alerts

- If you would like to filter the Defender alerts based on alert severity or alert status, click on `Parameters`, and set the `DefenderAlertSeverity` and `DefenderAlertStatus` property values accordingly.

- Allowed values for `DefenderAlertSeverity` parameter are listed below, kindly note all values are case-sensitive
	* High
	* Medium
	* Low
	* Informational
	* UnSpecified
	
- For example, if you want to filter the alert by "Medium" and "High" severity, you need to set the value as ["Medium","High"].
	
- Allowed values for `DefenderAlertStatus` parameter are listed below, kindly note all values are case-sensitive
	* New
	* InProgress
	* Resolved
	* Unknown

- For example, if you want to filter the alert by "New", you need to set the value as ["New"].

![logicapp01](Images/logicapp01.png)

- Save the Logic App.

## Disable Microsoft Defender for VMRay Storage Account

- Defender for storage will remove any malware uploaded to a Blob storage. If you are using Microsoft Defender for Storage you need to exclude the VMRay storage.

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Storage accounts` service.

![14](Images/14.png)

- Open the storage account, the name starts with `vmraystorage`.
- Go to `Microsoft Defender For Cloud`->`settings`, disable the `Microsoft Defender For Storage` and click on `save`.

![defender_disable](Images/defender_disable.png)

## Expected Issues With LogicApps
- Logic App `SubmitDefenderAlertsToVMRay` runs will fail after 2 minutes. This is a expected behaviour and is not an issue.

![32](Images/32.png)

    
## Debugging
- To debug and check logs after receiving an email, follow these steps:
  1. Navigate to the Azure Function App.
  2. Select the function that starts with "vmraydefender".
  3. In the Function section below, choose "VMRayDefender".
     ![d1](Images/d1.png)

  4. Go to the Invocation tab.
     ![d2](Images/d2.png)

  5. Find the execution based on the start time received in the email and match it with the invocation_id from the email.
     ![d3](Images/d3.png)

  6. Review all logs under the selected execution.
     

## Version History

| Version        | Release Date | Release Notes
|:---------------|:-------------|:---------------- |
| 1.0.0          | `26-05-2025` | <ul><li>Removed triple alert from VMRay IOC indicators: Previously, VMRAY submitted for each malicious files three hash values. With this change it only submit the SHA256 hash value.</li><li>Clear tags: One tag indicates Defender-AV or Defender-EDR detected the threat. Another tag indicates the threat name seen in Defender allowing to easily map VMRay submission and Defender alerts.</li><li>Retry logic and default adjusted.</li></ul> |
| 1.0.0-beta.2 	 | `25-03-2025` | <ul><li>Added the ability to filter the Defender Alerts by alert severity and alert status</li><li>Removed the dependency of Azure SaS Token from function app configuration</li><li>Bug Fixes</li></ul> |
| 1.0.0-beta.1   | `07-02-2025` | Initial Release |


## Steps to Update from 1.0.0-beta.2 to 1.0.0

### Deploy Function App
- Please re-dploy the Function App, following the instructions given in the document.[Deployment of Function App](#deployment-of-function-app)

### Deploy Logic App
- Please re-dploy the Logic App, following the instructions given in the document.[Submit-Defender-Alerts-To-VMRay Logic App Installation](#submit-defender-alerts-to-vmray-logic-app-installation)


## Steps to Update from 1.0.0-beta.1 to 1.0.0-beta.2 Version 

### Function App Installation

- Please re-deploy the Function App, following the instructions given in the document.[Deployment of Function App](#deployment-of-function-app)

### Submit-Defender-Alerts-To-VMRay Logic App Installation

- Please re-deploy the Logic App, following the instructions given in the document.[Submit-Defender-Alerts-To-VMRay Logic App Installation](#submit-defender-alerts-to-vmray-logic-app-installation)
