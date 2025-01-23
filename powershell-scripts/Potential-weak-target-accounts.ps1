# Load Active Directory Module
Import-Module ActiveDirectory

# Define timeframes
$twoYearsAgo = (Get-Date).AddYears(-2)
$oneYearAgo = (Get-Date).AddYears(-1)
$sixMonthsAgo = (Get-Date).AddMonths(-6)

# Output file paths
$legacyAccountsFile = "C:\Temp\Reports_LegacyAccounts.csv"
$inactiveAccountsFile = "C:\Temp\Reports_InactiveAccounts.csv"

# Create arrays to store results
$legacyAccountsResults = @()
$inactiveAccountsResults = @()

# Get legacy accounts
Write-Output "Identifying legacy accounts..."
$legacyAccounts = Get-ADUser -Filter * -Property WhenCreated, PasswordLastSet, PasswordNeverExpires, Enabled | Where-Object {
    $_.WhenCreated -lt $twoYearsAgo -and
    $_.PasswordLastSet -lt $oneYearAgo -and
    $_.PasswordNeverExpires -eq $true
}

# Collect legacy accounts into the results array
foreach ($account in $legacyAccounts) {
    Write-Output "Legacy account found: $($account.SamAccountName)"
    $legacyAccountsResults += [PSCustomObject]@{
        UserName             = $account.SamAccountName
        DisplayName          = $account.Name
        WhenCreated          = $account.WhenCreated
        PasswordLastSet      = $account.PasswordLastSet
        PasswordNeverExpires = $account.PasswordNeverExpires
        Enabled              = $account.Enabled
    }
}

# Get inactive accounts
Write-Output "Identifying inactive accounts..."
$inactiveAccounts = Get-ADUser -Filter * -Property LastLogonDate, Enabled | Where-Object {
    $_.LastLogonDate -lt $sixMonthsAgo -or
    $_.LastLogonDate -eq $null
}

# Collect inactive accounts into the results array
foreach ($inactiveAccount in $inactiveAccounts) {
    Write-Output "Inactive account found: $($inactiveAccount.SamAccountName)"
    $inactiveAccountsResults += [PSCustomObject]@{
        UserName    = $inactiveAccount.SamAccountName
        DisplayName = $inactiveAccount.Name
        LastLogon   = $inactiveAccount.LastLogonDate
        Enabled     = $inactiveAccount.Enabled
        Status      = "Inactive"
    }
}

# Export results to CSV
Write-Output "Exporting results to CSV files..."
$legacyAccountsResults | Export-Csv -Path $legacyAccountsFile -NoTypeInformation -Encoding UTF8
$inactiveAccountsResults | Export-Csv -Path $inactiveAccountsFile -NoTypeInformation -Encoding UTF8

Write-Output "Reports generated:"
Write-Output "Legacy Accounts Report: $legacyAccountsFile"
Write-Output "Inactive Accounts Report: $inactiveAccountsFile"

Write-Output "Script completed successfully."
