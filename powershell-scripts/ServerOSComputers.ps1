# Import Active Directory module
Import-Module ActiveDirectory

# Define the output CSV file path
$outputFile = "C:\temp\KerberoastingVulnerableAccounts.csv"

# Get AD user accounts with SPN set (vulnerable to Kerberoasting)
$kerberoastVulnerableAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, Description, LastLogonDate, PasswordNeverExpires, PasswordLastSet, SamAccountName

# Select the required properties and export to CSV
$kerberoastVulnerableAccounts | Select-Object `
    Name,
    Description,
    @{Name="LastLogon";Expression={[datetime]::FromFileTime($_.LastLogonDate)}},  # Convert LastLogonDate to readable format
    PasswordNeverExpires,
    @{Name="PasswordLastSet";Expression={$_.PasswordLastSet}},
    SamAccountName | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Export completed. The file is saved at: $outputFile"
