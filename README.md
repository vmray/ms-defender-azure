# Microsoft Defender for Endpoint Azure Connector for VMRay Advanced Malware Sandbox

**Latest Version:** beta - **Release Date:** 

## Overview

This project is an integration between Microsoft Defender for Endpoint and VMRay products: Analyzer, FinalVerdict and Totalinsight. 
The connector will collect alerts and related evidences, and query or submit these samples into VMRay Sandbox.
It accelerates the triage of alerts by adding comments to the alert in MS Defender Console with the analysis of the sample.
It also retrieves IOC values from VMRay and submits them into Microsoft Defender for Endpoint.

## Solution Overview
- The connector is built using Azure logic app, Azure functions app and Azure Storage.
  1. Azure Logic app `SubmitDefenderAlertsToVMRay` monitors the alerts from MS Defender as soon any AV/EDR alert are generated. If any AV/EDR alert is found, it will send the alert details to the Azure function app `VMRayDefender`.
  2. Azure function app `VMRayDefender` checks if the alert contains a file and checks if the file hash has already been analyzed by VMRay.
  3. If the hash was already analysed, the system checks if user configure to reanalyse the hash in configuration step, if yes it resubmits that to VMRay to reanalyse, if not it skips re-examining it.
  4. Azure function app `VMRayDefender` requests the file from Microsoft Defender by starting a live response session.
  5. Microsoft Defender starts a live response session that run PowerShell code on the endpoint. The power shell moves the files out of quarantine to a temporary folder before sending to Azure storage(vmray-defender-quarantine-files) container. 
  6. Azure function app `VMRayDefender` monitors the Azure storage(vmray-defender-quarantine-files) container and submits the quarantine file to VMRay.
  7. Azure function app `VMRayDefender` will wait till the submission is completed and When the VMRay analysis is done VMRay results are sent back to the Azure function app `VMRayDefender`.
  8. The Azure function app `VMRayDefender` post the results as a note within the relevant defender alert.
  9. If configured to send IOCs, the Azure function app `VMRayDefender` provides the IOCs as the indicators to Microsoft Defender that may use them for automatically alerting or blocking.
  10. Once the Azure function app `VMRayDefender` completes its process, it generates a JSON file named after the Defender Alert ID and uploads it to the Azure Storage Container: vmray-defender-functionapp-status. This JSON file contains all the details of the process.
  11. The Azure Logic App `SendEmailNotification` monitors the vmray-defender-functionapp-status container for new files. When a new file is detected, it sends an email notification to the configured recipient in logic app.

![solution_overview](Images/solution_overview.png)

## Requirements
- Microsoft Defender for Endpoint.
- VMRay Analyzer, VMRay FinalVerdict, VMRay TotalInsight.
- Microsoft Azure
  1. Azure functions with Flex Consumption plan.
     Reference: https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-plan
  2. Azure Logic App with Cunsumption plan.
     Reference: https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-pricing#consumption-multitenant
  3. Azure storage with Standard general-purpose v2.

## VMRay Configurations

- In VMRay Console, you must create a Connector API key.Create it by following the steps below:
  
  1. Create a user dedicated for this API key (to avoid that the API key is deleted if an employee leaves)
  2. Create a role that allows to "View shared submission, analysis and sample" and "Submit sample, manage own jobs, reanalyse old analyses and regenerate analysis reports".
  3. Assign this role to the created user
  4. Login as this user and create an API key by opening Settings > Analysis > API Keys.
  5. Please save the keys, which will be used in confiring the Azure Function.

     
## Microsoft Defender for Endpoint Configurations

### Creating Application for API Access

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Microsoft Entra ID` service.

![01](Images/01.png)

- Click `Add->App registration`.

![02](Images/02.png)

- Enter the name of application and select supported account types and click on `Register`.

![03](Images/03.png)

- In the application overview you can see `Application Name`, `Application ID` and `Tenant ID`.

![04](Images/04.png)

- After creating the application, we need to set API permissions for connector. For this purpose,
  - Click `Manage->API permissions` tab
  - Click `Add a permission` button
  - Select `APIs my organization uses`
  - Search `WindowsDefenderATP` and click the search result

![05](Images/05.png)

- On the next page select `Application Permissions` and check permissions according to the table below. And click `Add permissions` button below.

|       Category       |   Permission Name   |    Description   |
|:---------------------|:--------------------|:---------------- |
| Alert                | Alert.Read.All      | Needed to retrieve alerts and related evidence  |
| Alert                | Alert.ReadWrite.All | Needed to enrich alerts with sample information  |
| Machine              | Machine.LiveResponse | Needed to gather evidences from machines |
| Machine              | Machine.Read.All | Needed to retrieve information about machines  |
| Ti                   | Ti.Read.All | Needed to retrieve indicators  |
| Ti                   | Ti.ReadWrite | Needed to retrieve and submit indicators (application specific)|
| Ti                   | Ti.ReadWrite.All | Needed to retrieve and submit indicators (general) |
| Library              | Library.Manage | Needed to upload custom ps1 script for retrieving av related evidences |

![06](Images/06.png)

- After setting only the necessary permisions, click the `Grant admin consent for ...` button to approve permissions.

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

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Deploy a custom template` service.

![11](Images/11.png)

- On the next page select `Build your own template` in the editor.
  
![12](Images/12.png)

- Copy `azuredeploy.json` contents from the `FunctionApp` folder and save it.

![13](Images/13.png)

- On the next page, please provide the values accordingly.
  
![13a](Images/13a.png)

|       Fields       |   Description |
|:---------------------|:--------------------
| Subscription		| Select the appropriate Azure Subscription    | 
| Resource Group 	| Select the appropriate Resource Group |
| Region			| Based on Resource Group this will be uto populated |
| Function Name		| Please provide a function name if needed to change the default value|
| Azure Client ID   | Enter the Azure Client ID created in the App Registration Step |
| Azure Client Secret | Enter the Azure Client Secret created in the App Registration Step |
|Azure Tenant ID | Enter the Azure Tenant ID of the App Registration |
| Azure Storage Connection String| Please leave this empty |
| Azure Storage Saas Token| Please leave this empty |
| App Insights Workspace Resource ID | Go to `Log Analytics workspace` -> `Settings` -> `Properties`, Copy `Resource ID` and paste here |
| Vmray Base URL | VMRay Base URL |
| Vmray API Key | VMRay API Key |
| Vmray Resubmit | If true, the files will be resubmitted to VMRay analyser, even if the file hash was found in VMRay |
| Vmray API Retry Timeout | Provide maximum time to wait in minutes, when VMRay API is not responding |
| Vmray API Max Retry | Provide number of retries, when VMRay API is not responding |
| Vmray Analysis Job Timeout | Provide maximum time to wait in minutes, when VMRay Job submissions is not responding |
| Defender API Retry Timeout | Provide maximum time to wait in minutes, when Microsoft Defender API is not responding. |
| Defender API Max Retry | Provide number of retries, when Microsoft Defender API is not responding |
| Machine Availability Timeout | Provide maximum time to wait in minutes, when the machine is not responding |
| Machine Availability Retry | Provide number of retries, when machine is not responding |
| Create Indicators In Defender | If true, Indicators will be created in Microsoft Defender |
| Vmray Sample Verdict | Based on the selection, Indicators will be created in Microsoft Defender |
| Defender Indicator Action | The action that is taken if the indicator is discovered in the organization |
| Defender Indicator Alert | True if alert generation is required, False if this indicator shouldn't generate an alert|
	
- Once you provide the above values, please click on `Review + create` button.

### Deployment of Function App Zip package

- Download the zip package from the `FunctionApp` folder.
- Open [https://portal.azure.com/](https://portal.azure.com) and search `Storage accounts` service.

![14](Images/14.png)

- Open the storage account, the name starts with `vmraystorage`.
- Go to `Storage Browser` -> `Blob Containers`, click on container, the name starts with `vmraycontainer`.
- Click on `Switch to Access key`.

![15a](Images/15a.png)

- Upload the downloaded zip package to the container. 

![15](Images/15.png)

- Go to `Security + networking` -> `Access keys`, Copy `Connection string` and save it temporarily for next steps.

![16](Images/16.png)

- Go to `Security + networking` -> `Shared access signature`, check all the options under `Allowed resource types`, provide `End`(expiration time, preferred 06 months), click on `Generate SAS and connection string`.

![17](Images/17.png)

- Copy `SAS token` and save it temporarily for next steps.

![18](Images/18.png)

### Configuration of Function App

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Function App` service.

![19](Images/19.png)

- Open the VMRay FunctionApp name starts with `vmraydefender`.
- Go to `Settings`->`Environment variables`, double-click `AzureStorageConnectionString` and provide the connection string value copied in the previous step and click on `save`.
- Go to `Settings`->`Environment variables`, double-click `AzureStorageSaasToken` and provide the Saas token value copied in the previous step and click on `save`.
- Click on `Apply` -> `Confirm` buttons.

![20](Images/20.png)

- Go to `Overview` -> click on `Restart`.

![21](Images/21.png)

## Microsoft Azure Logic App Installation And Configuration

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Deploy a custom template` service.

![11](Images/11.png)

- On the next page select `Build your own template` in the editor.
  
![12](Images/12.png)

- Copy `azuredeploy1.json` contents from the `LogicApp` folder and save it.
- On the next page, provide the appropriate `Subscription` and `Resource group` and click on `Review & create`.

  **Note**: When deploying the function app if you chose a different name, please kindly provide the same name here as well.
  
  
![22](Images/22.png)

- Once the deployment is complete, go to newly deployed logic app, click on edit. The logic app will open in a designer mode.
- Click on the `WDATP Trigger`, click on `Add new`.

![23](Images/23.png)

- On the next page, choose `Authentication` as `Service prinicipal`, and provide appropriate values.

![24](Images/24.png)
![25](Images/25.png)

- Click on `Alerts - Get single Alert` action, click on `Cheange connection` and select the connection created above.

![24a](Images/24a.png)

- Save the Logic App.

- Open [https://portal.azure.com/](https://portal.azure.com) and search `Deploy a custom template` service.

![11](Images/11.png)

- On the next page select `Build your own template` in the editor.
  
![12](Images/12.png)

- Copy `azuredeploy2.json` contents from the `LogicApp` folder and save it.
- On the next page, provide the appropriate `Subscription` and `Resource group` and click on `Review & create`.

![26](Images/26.png)

- Once the deployment is complete, go to newly deployed logic app, click on edit. The logic app will open in a designer mode.
- Click on the `Azure Blob Trigger`, click on `Change connection` and click on `Add new` on the following page.

![27](Images/27.png)

- Provide appropriate values and click on `Create new`.

![28](Images/28.png)

- Click on `folder icon` on the `Container box`.

![28a](Images/28a.png)

- Select folder named `vmray-defender-functionapp-status`

![28b](Images/28b.png)  
  
- Click on `Get blob content` action, click on `Change connection`.

![29](Images/29.png)

- Select the connection created in the above step.

![30](Images/30.png)

- Do the same `Delete blob` action, click on `Change connection` and select the connection created in the above step.

- Click on `Send an Email(V2)` action, click on `Change connection` and click on `Add new` , provide appropriate connection.

 ![31](Images/31.png) 

- Save the Logic App.


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


## Expected Issues With LogicApps
- Logic App `SubmitDefenderAlertsToVMRay` runs will fail. This is a expected behaviour.
- In Logic App **Consumption Plan**, each API call runs for a maximum of **2 minutes** before retrying the process. This is the default behavior for consumption-based Logic Apps. Since this Logic App is calling the `VMRayDefender` function app and the process might take more than 2m to finish, the Logic App will fail. But the `VMRayDefender` function app will do all the work behind and let the customers know once the analyisis is completed

![32](Images/32.png)

**Why 2 playbooks Approach**
  - To overcome the **2 minutes**  isssue, we need to deploy the Logic apps with the **Standard Plan**, it would cost approximately $175 per month.To avoid this extra cost, we created an additional Logic App that monitors whether the previous Logic App succeeded or failed.
 - It then notifies the customer via email, allowing them to stay in sync with the process.
    
