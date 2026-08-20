# Encrypted-passthrough variant.
#
# Uploads Defender quarantine artifacts to Azure Blob Storage *as-is*, still
# RC4-encrypted by Defender. The Azure Function decrypts server-side using
# the published mpengine.dll key. No Defender exclusion folder is created;
# no plaintext malware is ever written to disk on the endpoint.
#
# Live Response runs as NT AUTHORITY\SYSTEM, which has read access to the
# normally SYSTEM-only directories under
#     C:\ProgramData\Microsoft\Windows Defender\Quarantine\
#
# Args (passed by run_av_submission_script):
#   $args[0]  threat_name (informational only here; used downstream)
#   $args[1]  storage account name
#   $args[2]  container name
#   $args[3]  SHA-256 list joined by 'vmray' (informational; server filters)

$signedAuthorizationKey = "${SAS_TOKEN}"

$quarantineRoot   = "C:\ProgramData\Microsoft\Windows Defender\Quarantine"
$entriesRoot      = Join-Path $quarantineRoot "Entries"
$resourceDataRoot = Join-Path $quarantineRoot "ResourceData"

# Limit to artifacts touched recently. The alert that triggered this run is
# recent, so the matching quarantine entry is too. Avoids re-uploading the
# whole quarantine history on busy endpoints.
$lookbackHours = 24

function Upload-Blob
{
    param(
        [string]$accountName,
        [string]$containerName,
        [string]$blobName,
        [string]$filePath
    )
    $blobUrl = "https://$accountName.blob.core.windows.net/$containerName/$blobName$signedAuthorizationKey"
    $headers = @{ "x-ms-blob-type" = "BlockBlob" }
    try
    {
        $fileContent = [System.IO.File]::ReadAllBytes($filePath)
        Invoke-RestMethod -Uri $blobUrl -Method Put -Headers $headers -Body $fileContent -ContentType "application/octet-stream"
        return $true
    }
    catch
    {
        Write-Host "Failed to upload $blobName : $_"
        return $false
    }
}

function Submit-EncryptedQuarantine
{
    param(
        [string]$accountName,
        [string]$containerName,
        [string]$evidences
    )

    if (-not (Test-Path $quarantineRoot))
    {
        Write-Host "No Quarantined Files Found"
        return
    }

    # Per-run prefix so the Function App can find this batch and so concurrent
    # runs on different endpoints don't collide in the shared container.
    $sessionId = "$([Environment]::MachineName)/$(Get-Date -Format 'yyyyMMddHHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $cutoff    = (Get-Date).AddHours(-$lookbackHours)

    Write-Host "SessionId: $sessionId"
    Write-Host "EvidenceHashes: $evidences"

    $entriesUploaded   = 0
    $resourcesUploaded = 0

    if (Test-Path $entriesRoot)
    {
        Get-ChildItem -Path $entriesRoot -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            ForEach-Object {
                $blob = "$sessionId/Entries/$($_.Name)"
                if (Upload-Blob -accountName $accountName -containerName $containerName -blobName $blob -filePath $_.FullName)
                {
                    $entriesUploaded++
                }
            }
    }

    if (Test-Path $resourceDataRoot)
    {
        Get-ChildItem -Path $resourceDataRoot -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff } |
            ForEach-Object {
                $rel  = $_.FullName.Substring($resourceDataRoot.Length).TrimStart('\').Replace('\','/')
                $blob = "$sessionId/ResourceData/$rel"
                if (Upload-Blob -accountName $accountName -containerName $containerName -blobName $blob -filePath $_.FullName)
                {
                    $resourcesUploaded++
                }
            }
    }

    if ($entriesUploaded -eq 0 -and $resourcesUploaded -eq 0)
    {
        # No recent quarantine artifacts. Don't emit QuarantinedFilesFound; the
        # Function App's existing retry loop will wait and re-invoke us.
        Write-Host "No Quarantined Files Found"
        return
    }

    Write-Host "QuarantinedFilesFound"
    Write-Host "EntriesUploaded: $entriesUploaded  ResourcesUploaded: $resourcesUploaded"
}

Submit-EncryptedQuarantine -accountName $args[1] -containerName $args[2] -evidences $args[3]
