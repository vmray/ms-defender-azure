# VMRay Defender for Endpoint Azure Connector — Deployment Guide

This repository contains the components and instructions to deploy the VMRay connector for Microsoft Defender for Endpoint. The connector collects Defender AV/EDR alerts, submits the related files and URLs to the VMRay sandbox, and enriches the Defender alerts and incidents with the analysis results.

---

## Introduction

### Microsoft Defender for Endpoint + VMRay

This project is an integration between Microsoft Defender for Endpoint and VMRay (FinalVerdict / TotalInsight). It collects alerts and their evidence, then queries or submits the samples to the VMRay Sandbox so your SOC team can better understand the threat behind an alert. It:

- Accelerates alert triage by posting VMRay analysis as a note on the Defender alert
- Optionally appends the same enrichment as a comment on the parent Defender **incident** (with per-incident dedup)
- Improves protection by extracting IOCs and submitting them as Defender **indicators**
- Optionally adds VMRay verdict / threat-name **tags** to incidents

**Important:** This solution can only analyze files quarantined by Defender Antivirus, flagged by Defender EDR, or downloaded from a URL (child sample). It cannot access files that were removed or blocked outright.

### Solution Overview

The connector is built from an Azure **Logic App**, an Azure **Function App**, and Azure **Storage**:

1. The Logic App `SubmitDefenderAlertsToVMRay` watches Defender for new AV/EDR alerts and forwards their details to the Function App `VMRayDefender`.
2. The Function App checks whether the file hash / URL was already analyzed by VMRay. If the last analysis is older than `VmrayResubmitAfter` (default 7 days), it resubmits; otherwise it reuses the previous result.
3. For files, a Live Response session either downloads the file directly (EDR-detected files) or uploads the still-encrypted quarantine artifact straight from Defender's quarantine store to the `vmray-defender-quarantine-files` storage container (Antivirus-quarantined files) — the file is never restored to disk or written to a temporary folder on the endpoint. The Function App decrypts and submits it to VMRay. For URLs, the evidence is taken directly from the alert.
4. When analysis completes, results are posted back to the Defender alert (and, if configured, to the incident as comments/tags and as Defender indicators).

![solution_overview](Images/solution_overview.png)

### About VMRay

VMRay is a leading provider of automated malware analysis and advanced threat detection. Using hypervisor-based sandboxing, VMRay delivers deep visibility into sophisticated and evasive threats.

---

## Prerequisites

| Requirement | Why |
|---|---|
| **Azure Subscription** | To host the Function App, Logic App, and Storage |
| **Global Administrator** (in your Microsoft 365 / Entra tenant) | The connector uses **application permissions** (WindowsDefenderATP + Microsoft Graph) that require tenant-wide admin consent |
| **Microsoft Defender for Endpoint** | The source of the alerts being enriched |
| **VMRay Analyzer / FinalVerdict / TotalInsight** | The sandbox that analyzes the samples |
| **VMRay Connector API key** | Created in the VMRay Console (see below). Used to configure the Function App |
| **PowerShell environment** | Azure Cloud Shell (PowerShell) is the recommended way to run the script |

### Create a VMRay Connector API key

In the VMRay Console:

1. Create a dedicated user for this API key (so the key isn't deleted if an employee leaves).
2. Create a role that allows *"View shared submission, analysis and sample"* and *"Submit sample, manage own jobs, reanalyse old analyses and regenerate analysis reports"*.
3. Assign the role to the user.
4. Sign in as that user and create an API key under **Settings → Analysis → API Keys**.
5. Save the key — you'll paste it into the script during Phase 2.

---

## Deployment Overview

The entire Azure-side deployment is driven by a single interactive PowerShell script that handles three phases:

| Phase | What it does | Manual? |
|---|---|---|
| **0. Pre-flight** | Loads modules, connects to Microsoft Graph + Azure, offers a subscription picker, creates/reuses the resource group | Automated |
| **1. App Registration** | Creates (or reuses) the Entra App Registration, adds the WindowsDefenderATP + Microsoft Graph **application** permissions, mints a client secret | Automated |
| **1.5. Admin consent** | Grants admin consent **programmatically** if you have the directory role; otherwise prints a one-time URL for a Global Admin to click (can be deferred) | Auto, or **manual click** |
| **1.6. Defender + Intune** | Prints a checklist for the two things Azure APIs can't automate (Defender Advanced Features + Intune settings) | **Manual (portal)** |
| **2. Function App** | Deploys the Function App (Flex Consumption or Premium) via ARM, then **auto-fills** the `AzureStorageConnectionString` + `AzureStorageAccountKey` settings and restarts (the README's manual "copy the storage key" step, done for you) | Automated |
| **3. Logic App** | Deploys the Logic App (Consumption or Standard) via ARM. For **Standard**, it also sets the `AzureClientID` / `AzureClientSecret` / `AzureTenantID` app settings automatically | Automated |
| **3.5. Connection authorization** | Authorize the `wdatp` connection (and, for Standard, fill the `connections.json` JSON-View placeholders — the script prints the exact values) | **Manual (portal)** |

**Total customer-side effort: one PowerShell command + one admin-consent click (if you can't self-grant) + the Defender/Intune toggles + the Logic App connection authorization.**

The manual steps that **cannot** be automated via Azure APIs are called out by the script at the right moment.

---

## Quick Start — Cloud Shell

### Step 1 — Open Cloud Shell

1. Sign in to the [Azure Portal](https://portal.azure.com) with your tenant administrator account.
2. Click the **`>_`** Cloud Shell icon in the top-right toolbar.
3. Choose **PowerShell** if prompted.

### Step 2 — Upload the deployment script

Click **Manage files → Upload** in the Cloud Shell toolbar and upload:

- `Scripts/Deploy-VMRayDefenderConnector.ps1`

The ARM templates (Function App + Logic App) are fetched directly from GitHub by the script — no need to upload them.

### Step 3 — Run the deployment script

```powershell
./Deploy-VMRayDefenderConnector.ps1
```

The script is fully interactive — it prompts for everything it needs. Default values appear in brackets; press Enter to accept.

> **Offline / local override:** If you've customized a template or your environment can't reach GitHub, upload the JSON(s) alongside the script and pass them explicitly:
> ```powershell
> ./Deploy-VMRayDefenderConnector.ps1 -FunctionTemplateFile ~/azuredeploy.json -LogicTemplateFile ~/premiumazuredeploy.json
> ```
> Local files take precedence over the default GitHub URLs.

You'll be asked (in order):

| Prompt | What to enter |
|---|---|
| Confirm tenant + subscription | If only one subscription is accessible, press Enter to confirm. If multiple are accessible, the script offers a picker — choose 1 for the current one, or 2 to pick another. |
| Resource group name | Existing RG, or a new name (created if missing). **The Function App and Logic App must share this RG.** |
| Azure region | **Only asked if the RG is new.** If you reused an existing RG, its location is used automatically. |
| Create new or use existing App Registration? | Choose **1 (new)** for a first-time deployment. |
| Display name for the new App Registration | Press Enter for default (`VMRay-Defender-Connector-App`). |
| **Open the printed consent URL → sign in as a Global Admin → click Accept** | (Only if the script couldn't grant consent programmatically.) |
| Consent step: `[1] verify now`  or  `[2] Skip` | Choose **1** if consent was just granted (verifies, waits up to 90s). Choose **2** to defer — the URL is reprinted at the end to forward to an admin. |
| Which Function App hosting plan? | **1 Flex Consumption** (check region support) or **2 Premium**. |
| Function App base name | Press Enter for default (`VMRayDefender`). Must be **< 20 characters**, letters/numbers/hyphens. A 3-char uniqueness hash is appended automatically. |
| Log Analytics workspace | Pick one from the list, or paste a full `/subscriptions/.../workspaces/...` Resource ID. |
| VMRay Base URL | **1** `https://eu.cloud.vmray.com`, **2** `https://us.cloud.vmray.com`, or **3** to enter your own. |
| VMRay API Key | Paste your VMRay connector API key (input hidden; required). |
| Configure advanced connector settings? | Press Enter for **No** (sensible defaults). Choose **Yes** to set resubmit window, indicators, tags, comments, quarantine fetch, verdict, and alert-title filter. |
| Proceed with Function App deployment? | Press Enter to confirm. |
| Which Logic App plan? | **1 Consumption** (default) or **2 Standard**. |
| Logic App name | Press Enter for default (`SubmitDefenderAlertsToVMRay`). For **Standard**, the name must be globally unique — the script checks and re-prompts if it's taken. |
| Proceed with Logic App deployment? | Press Enter to confirm. |

The deployment runs for several minutes per phase (a Function App or Standard Logic App deploy can take 5-10 minutes with no console output while Kudu unpacks the package — this is normal, don't cancel).

### Step 4 — Complete the manual steps the script prints

After Phase 1 the script prints the **Defender + Intune** checklist; after Phase 3 it prints the **connection-authorization** values. Complete them as described in [Manual Steps](#manual-steps-cannot-be-automated) below.

### Step 5 — Verify

See the [Verification](#verification) section.

---

## Re-deployment / Reusing an Existing App Registration

If you already have an App Registration from a previous deployment (e.g., re-running after a failure, or sharing one App Reg):

When prompted *"How do you want to handle the App Registration?"*, choose **option 2 — Use an existing App Registration** (or pass `-AppId`).

The script will:

1. Look up the App Registration by Client ID.
2. Ensure the required WindowsDefenderATP + Graph application permissions are present (adds any missing ones).
3. Ask whether to paste your existing client secret or mint a fresh one.
4. Verify admin consent is already granted (or run the consent step if not).
5. Continue with the Function App and Logic App deployments as normal.

You can also run one phase at a time with the skip flags:

```powershell
# Re-run only the Function App phase, reusing an existing App Reg
./Deploy-VMRayDefenderConnector.ps1 -AppId "abc1234-..." -SkipLogicApp

# Re-run only the Logic App phase
./Deploy-VMRayDefenderConnector.ps1 -AppId "abc1234-..." -SkipAppReg -SkipFunctionApp
```

The script is idempotent at every step, and includes safeguards for same-RG re-deploys (it pre-clears the stale storage role assignment and the leftover `WaitSection` deployment script that would otherwise conflict).

---

## Manual Steps

The script prints each of these at the right moment. They're listed here for reference.

### A. Admin consent (only if not granted programmatically)

If the script operator lacks the directory role to grant consent, the script prints:

```
https://login.microsoftonline.com/YOUR-TENANT-ID/adminconsent?client_id=YOUR-APP-CLIENT-ID
```

A Global Administrator opens it once and clicks **Accept**. The connector won't work until this is done.

### B. Defender portal — Advanced Features

Open [https://security.microsoft.com](https://security.microsoft.com) → **Settings → Endpoints → Advanced features**, and enable:

- **Live Response**
- **Live Response for Servers**
- **Live Response unsigned script execution**

### C. Intune — Antivirus policy

- Set the remediation action to **Quarantine** for all threat levels (Endpoint security → Antivirus → your policy → Defender configuration).

### D. Logic App connection authorization

**Consumption plan:**

1. Open the Logic App → **Edit** (designer).
2. On the **WDATP** connection, set Authentication = **Service principal** and enter the `Client ID`, `Client Secret`, and `Tenant ID` (printed in the final summary).
3. On the **Alerts - Get single alert** action, click **Change connection** and select the connection you just created. Save.

**Standard plan:** the script sets the credential app settings for you, but the `connections.json` still has literal placeholders to fill:

1. **Authorize** the `wdatp` API connection (wdatp connection → General → Edit API Connection → Authorize → Save).
2. Open the Logic App → **Workflow → Connections → JSON View** and replace the placeholders with the values the script printed:
   - `<sub_id>`, `<resourceGroupName>`, `<location>`, `<function_name>`, `<Function Key>`
3. Save.

### E. Disable Microsoft Defender for the VMRay Storage Account

Defender for Storage will remove any malware uploaded to Blob storage. If you use Defender for Storage, open the `vmraystorage*` account → **Microsoft Defender for Cloud → Settings**, disable **Microsoft Defender for Storage**, and Save.

---

## Verification

### Logic App runs

- A run of `SubmitDefenderAlertsToVMRay` that **fails after ~2 minutes is expected behaviour** and is not an issue (it's the polling trigger timing out until an alert arrives).

### Function App logs (end-to-end)

1. Trigger (or wait for) a Defender AV/EDR alert.
2. In the Azure Portal, open the Function App whose name starts with `vmraydefender`.
3. Under **Functions**, choose **VMRayDefender** → **Invocations**.
4. Find the execution matching the alert time and review the logs — you should see the sample being submitted to VMRay.
5. Open your VMRay portal (e.g., `https://us.cloud.vmray.com`) → **Submissions**. Within a couple of minutes the sample should appear.

If the alert is enriched with a VMRay note (and, if configured, indicators/tags/incident comments), the deployment is working end-to-end.

---

## Troubleshooting

### Consent verification didn't see all permissions granted

**What's happening:** After Accept, Microsoft's grant database takes 10-90 seconds (occasionally longer) to propagate to the Graph API the script uses to verify. The script checks immediately, then retries up to 90 seconds.

**What to do:** the script offers a recovery menu:

1. **Wait another 90s and re-check** — the most common fix; propagation is often just slow.
2. **Re-open the consent URL** — if the first Accept click may not have registered (try an InPrivate/Incognito window).
3. **I've confirmed consent in the Portal — continue as granted** — if you can see the green checkmarks under Entra ID → App registrations → your app → API permissions, but Graph hasn't caught up.
4. **Skip** — defer and forward the URL to an admin later.

### Standard Logic App fails with `InternalServerError` on `wdatp/wdatp`

**Symptom:** the Standard Logic App deployment sits at "Deploying ARM template..." for ~5 minutes, then the deployment shows a failed `Microsoft.Web/connections/accessPolicies` resource named `wdatp/wdatp` with `InternalServerError`.

**Cause:** the access-policy child resource shares the static name `wdatp` with its parent connection, which collides.

**Fix:** use a Logic App template whose access-policy `name` is unique (e.g. `[parameters('logicAppName')]` instead of the static `"wdatp"`), and deploy it via `-LogicTemplateFile`:

```powershell
./Deploy-VMRayDefenderConnector.ps1 -LogicTemplateFile ~/premiumazuredeploy.json
```

### Function App deployment fails with "internal server error"

**Symptom:** the ARM deployment fails, and the failed resource is the code-push extension (`onedeploy` on Flex, `zipdeploy` on Premium).

**Cause:** the extension polls Kudu synchronously with a fixed timeout. On a slow deploy Kudu keeps working in the background but the extension reports a `500`. It's usually transient.

**Fix:** re-run the deployment. It's idempotent, and because the infrastructure already exists the retry is faster. If it fails again on the *same* resource, check the deployment's operation details for the real inner error.

### Managed identity replication ("PrincipalNotFound")

**What's happening:** on a same-RG re-deploy, ARM reaches the storage role assignment before the Function App's new managed identity has replicated to Entra ID.

**What the script does:** it retries the Function App deployment up to 3 times, waiting 60s between attempts for replication to catch up. Usually no action needed.

### Function App base name rejected

**Symptom:** *"Must be fewer than 20 characters; letters, numbers and hyphens only."*

**Cause:** the base name plus the appended uniqueness hash must stay within Azure's limits. Choose a shorter name.

### Multiple App Registrations with the same name

The script warns if an App Registration with your chosen display name already exists and lets you either reuse the name or enter a different one — so previous test deployments won't silently create duplicates.

---

## Summary — Comparison with the Original (Manual) Flow

| Step | Original (manual portal flow) | New (script-driven) |
|---|---|---|
| App Registration + permissions + secret | ~20 portal clicks | Automated |
| Admin consent | Manual click | Auto (or manual click, unavoidable) |
| Function App deployment | Portal "Deploy to Azure" | Auto via script |
| Copy storage key → Function App settings + restart | Manual copy/paste across blades | **Automated** |
| Logic App deployment | Portal "Deploy to Azure" | Auto via script |
| Logic App credential settings (Standard) | Manual JSON-View + designer edits | Credentials **auto-set**; only connection auth + placeholders remain |
| Defender Advanced Features + Intune | Manual | Manual (unavoidable) |
| Logic App connection authorization | Manual | Manual (unavoidable) |

The single-command deployment is the recommended path for all new installations. The legacy step-by-step guide in the original `README.md` remains available for reference.
