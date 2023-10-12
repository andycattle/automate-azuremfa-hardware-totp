#requires -version 5

<#
.SYNOPSIS
  Programmatically add hardware tokens to Microsoft Azure MFA

.DESCRIPTION
  
  ** NOTE **
  This script uses undocumented Microsoft API calls and should be used with caution.

  Pre-Requisite:
  
  - Azure Powershell Module: `Install-Module -Name Az -AllowClobber`
  - CSV file in the Azure MFA Hardware token format
  - A PowerShell session pre-authenticated to Azure AD using `Connect-AzAccount`

  Basic Usage:
  .\Add-AzureMfaToken.ps1 -upn email.address@domain.com -serialNumber 000000000 -tokensCSV c:\pathTo\tokens.csv

  How it works:
    - Looks up serial number from specified CSV file
    - Updates UPN to the one specified
    - Uploads the entry to the Azure MFA service
    - Waits for upload to be processed
    - Generates an TOTP code using the current time and secret key
    - Activates the uploaded token using the generated code

  Attributions:
  Functions to generate Otp token by Jon Friesen:  https://gist.github.com/jonfriesen/234c7471c3e3199f97d5

.PARAMETER upn
  
  The user principal name of the account that the hardware fob is to be assigned to

.PARAMETER serialNumber

  The user principal name of the account to add to Azure MFA
  
.PARAMETER tokensCSV

  Path to CSV file containing hardware tokens, with the following headings (UPN to be left empty):
    
    upn,Serial Number,Secret Key,Time Interval,Manufacturer,Model

.PARAMETER activeToken

  Whether the token should be activated, defaults to true

.PARAMETER environment

  The Azure environment to use, defaults to AzureCloud.  Other option is AzureUSGovernment.

.NOTES
  Version:        1.0
  Author:         Andy Cattle
  Creation Date:  October 22nd, 2020
  Purpose/Change: Provide an way of automating upload of tokens to Azure MFA
#>

param (
		
  [Parameter( Mandatory = $true)]
  [string]$upn,

  [Parameter( Mandatory = $true)]
  [string]$serialNumber,

  [Parameter( Mandatory = $true)]
  [string]$tokensCSV,
  
  [Parameter (Mandatory = $false)]
  [bool]$activeToken = $true,

  [Parameter( Mandatory = $false)]
  [ValidateSet("AzureCloud", "AzureUSGovernment")]
  [string]$azureEnvironment = "AzureCloud"
)

# Function to get a one-time password for a given secret
function Get-Otp($Secret, $Length, $Window) {

  function Get-TimeByteArray($WINDOW) {
    $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $unixTime = [Convert]::ToInt64([Math]::Floor($span / $WINDOW))
    $byteArray = [BitConverter]::GetBytes($unixTime)
    [array]::Reverse($byteArray)
    return $byteArray
  }

  function Convert-HexToByteArray($hexString) {
    $byteArray = $hexString -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
    return $byteArray
  }

  function Convert-Base32ToHex($base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";

    for ($i = 0; $i -lt $base32.Length; $i++) {
      $val = $base32chars.IndexOf($base32.Chars($i));
      $binary = [Convert]::ToString($val, 2)
      $staticLen = 5
      $padding = '0'
      # Write-Host $binary
      $bits += Add-LeftPad $binary.ToString()  $staticLen  $padding
    }

    for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
      $chunk = $bits.Substring($i, 4)
      # Write-Host $chunk
      $intChunk = [Convert]::ToInt32($chunk, 2)
      $hexChunk = Convert-IntToHex($intChunk)
      # Write-Host $hexChunk
      $hex = $hex + $hexChunk
    }
    return $hex;

  }

  function Convert-IntToHex([int]$num) {
    return ('{0:x}' -f $num)
  }

  function Add-LeftPad($str, $len, $pad) {
    if (($len + 1) -ge $str.Length) {
      while (($len - 1) -ge $str.Length) {
        $str = ($pad + $str)
      }
    }
    return $str;
  }

  $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
  $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($SECRET.ToUpper())))
  $timeBytes = Get-TimeByteArray $WINDOW
  $randHash = $hmac.ComputeHash($timeBytes)
    
  $offset = $randHash[($randHash.Length - 1)] -band 0xf
  $fullOTP = ($randHash[$offset] -band 0x7f) * [math]::pow(2, 24)
  $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
  $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
  $fullOTP += ($randHash[$offset + 3] -band 0xff)

  $modNumber = [math]::pow(10, $LENGTH)
  $otp = $fullOTP % $modNumber
  $otp = $otp.ToString("0" * $LENGTH)

  return $otp
}

function Wait-AzMfaTokenUpload ($name, $apiHost, $tokenApplication) {

  $result = $false
  $pollPeriod = 5
  $numTries = 20
  $try = 0


  while ($result -eq $false -and $try++ -lt $numTries) {

    Start-Sleep -Seconds $pollPeriod    
    
    $context = Get-AzContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

    $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
      'x-ms-client-request-id'   = [guid]::NewGuid()
      'x-ms-correlation-id'      = [guid]::NewGuid()

    }

    Write-Host "Waiting for `"$name`" upload to complete, try $try/$numTries..."
        
    $testUrl = "https://$($apiHost)/api/MultiFactorAuthentication/HardwareToken/listUploads"

    $uploadStatus = Invoke-RestMethod -Uri $testUrl `
      -Headers $headers `
      -Method GET `
      -ContentType "application/json"


    Write-Host  $uploadStatus

    $currentUpload = $uploadStatus | Where-Object { $_.fileName -eq $name } | Select-Object -First 1

    if ($currentUpload) {
      if ($currentUpload.fileProcessingStatus -eq "CompletedWithNoErrors") {
        Write-Host "Token Upload Completed" -ForegroundColor Green
        return $true
      }
      elseif ($currentUpload.fileProcessingStatus -eq "CompletedWithErrors") {

        Write-Host "Token Upload Failed" -ForegroundColor Red
        return $false

      }

    }
    else {
      Write-Host "Error Uploading new Serial, no upload status found" -ForegroundColor Red
      return $false
    }
       
  }

  Write-Host "Upload issue, did not succeed in time" -ForegroundColor Red
  return $false
}

function Enable-AzMfaToken($upn, $serialNumber, $Secret, $apiHost, $imageHost, $tokenApplication) {

  $context = Get-AzContext
  $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

  $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
    'x-ms-client-request-id'   = [guid]::NewGuid()
    'x-ms-correlation-id'      = [guid]::NewGuid()
  }

  $tokenDetailsUrl = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/users?skipToken=&upn=$UPN&enabledFilter="

  $tokenDetail = Invoke-RestMethod -Uri $tokenDetailsUrl `
    -Headers $headers `
    -Method GET `
    -ContentType "application/json" `
  | Select-Object -ExpandProperty items `
  | Where-Object { $_.serialNumber -eq $serialNumber } `
  | Select-Object -First 1

  $oneTimePasscode = Get-Otp -SECRET $Secret -LENGTH 6 -WINDOW $tokenDetail.timeInterval

  $payload = @{

    displayName      = $tokenDetail.displayName
    enableAction     = "Activate"
    enabled          = $tokenDetail.enabled
    enabledImg       = "https://$($imageHost)/iam/Content/Images/Directories/directoryDeletionRequirementMet.svg"
    manufacturer     = $tokenDetail.manufacturer
    model            = $tokenDetail.model
    oathId           = $tokenDetail.oathId
    objectId         = $tokenDetail.objectId
    serialNumber     = $tokenDetail.serialNumber
    timeInterval     = $tokenDetail.timeInterval
    upn              = $tokenDetail.upn
    verificationCode = $oneTimePasscode
  } | ConvertTo-Json

  Write-Host "Attempting to activate token, upn: $($tokenDetail.upn), serial $($tokenDetail.serialNumber), otp: $oneTimePasscode"

  $MfaActivateUri = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/enable"

  $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
    'x-ms-client-request-id'   = [guid]::NewGuid()
    'x-ms-correlation-id'      = [guid]::NewGuid()
  }

  $activated = $false

  try {
    $activated = Invoke-RestMethod -Uri $MfaActivateUri `
      -Headers $headers `
      -Method POST `
      -ContentType "application/json" `
      -body $payload
  }
  catch {
    Write-Host "An Error Occurred: " -ForegroundColor Red
    $_.Exception.Response | Format-List    
  }

  if ($activated) {
    Write-Host "Success" -ForegroundColor Green
  }
  else {
    Write-Host "Failed" -ForegroundColor Red
  }

}
  
# Create a unique name used when uploading a new token
$uploadName = "$([guid]::NewGuid()).csv"

# Import CSV file and get line with matching serial number
$content = Import-Csv -Path $tokensCSV `
| Where-Object { $_."Serial Number" -eq $serialNumber } `
| Select-Object -First 1


# Check that content is valid
if ($content."Serial Number" -eq $serialNumber) {

  # Add UPN specified in parameters
  $content.upn = $upn

  # Convert to CSV and strip out quotation marks added by PowerShell command
  $contentCsvString = ($content | ConvertTo-Csv -NoTypeInformation | Out-String) -replace "`""

  # Create JSON payload for API call
  $payload = @{
    "id"       = $null
    "name"     = $uploadName
    "content"  = $contentCsvString
    "mimeType" = "application/vnd.ms-excel"
  } | ConvertTo-Json

  $uploaded = $false

  # Set variables based on Azure environment
  $apiHost = if ($azureEnvironment -eq "AzureUSGovernment") {"main.iam.ad.ext.azure.us"} else {"main.iam.ad.ext.azure.com"}
  $imageHost = if($azureEnvironment -eq "AzureUSGovernement"){"iam.hosting.azureportal.usgovcloudapi.net"} else {"iam.hosting.portal.azure.net"}
  $tokenApplication = if($azureEnvironment -eq "AzureUSGovernement"){"ee62de39-b9b0-4886-aa58-08b89c4e3db3"} else {"74658136-14ec-4630-ad9b-26e160ff0fc6"}

  try {

    # Endpoint for uploading hardware token
    $uploadUrl = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/upload"

    # Get authorization token
    $context = Get-AzContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

    # Headers for API call
    $headers = @{
      "Authorization"          = "Bearer $($token.AccessToken)"
      'x-ms-client-request-id' = [guid]::NewGuid()
      'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    # API request to upload a token
    $uploaded = Invoke-RestMethod -Uri $uploadUrl  `
      -Headers $headers `
      -Method POST `
      -ContentType "application/json" `
      -body $payload

  }
  catch {
    Write-Host "An Error Occurred: " -ForegroundColor Red
    $_.Exception.Response | Format-List
  }

  if ($uploaded -ne $false) {
            
    Write-Host "Uploaded Token Data" -ForegroundColor Green 
    # Poll upload until it applied

    $uploadState = Wait-AzMfaTokenUpload -name $uploadName 
            
    if ($uploadState -eq $true) {
      if($activeToken -eq $true) {
        # Activate token
        Enable-AzMfaToken -upn $upn -serialNumber $serialNumber -Secret $content.'Secret Key'
      }
    }
    else {

      Write-Host "Abandon, issue with upload" -ForegroundColor Red
    }
  }
}
else {
  Write-Host "Serial Number not Found" -ForegroundColor Red
}
