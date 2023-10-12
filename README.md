# Automate Azure MFA Hardware Tokens

PowerShell script that can help automate the process of importing and activating hardware TOPT tokens into Azure MFA. Currently there are no built-in PowerShell commands for this purpose.

## Warning

This script uses undocumented API endpoints and should be used with caution.

## Pre-Requisite:

- Azure Powershell Module: `Install-Module -Name Az -AllowClobber`
- CSV file from token supplier in the Azure MFA Hardware token format [Microsoft Documentation](https://docs.microsoft.com/en-gb/azure/active-directory/authentication/concept-authentication-oath-tokens#oath-hardware-tokens-preview):
  - `upn,Serial Number,Secret Key,Time Interval,Manufacturer,Model`

## Usage

- Authenticate a PowerShell session using `Connect-AzAccount`
- Run the command as follows:
```powershell
.\Add-AzureMfaToken.ps1 -upn email.address@domain.com -serialNumber 000000000 -tokensCSV c:\pathTo\tokens.csv
```

## Azure Government Support

This script also supports Azure Government environments. To use the script with Azure Government, specify the `-azureEnvironment` parameter with the value `AzureUSGovernment`. For example:

```powershell
.\Add-AzureMfaToken.ps1 -upn email.address@domain.com -serialNumber 000000000 -tokensCSV c:\pathTo\tokens.csv -environment AzureUSGovernment
```

## Attributions

Code to generate one time password by [Jon Friesen](https://gist.github.com/jonfriesen/234c7471c3e3199f97d5)
