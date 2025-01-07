$verbosepreference = "continue"  
  
$searchdate = "2019-01-01" #yyyy-MM-dd format  
$searchbase = "DC=ho,DC=domain,DC=com"  
  
$passwordsNotChangedSince = $([datetime]::parseexact($searchdate,'yyyy-MM-dd',$null)).ToFileTime()  
write-verbose "Finding users whose passwords have not changed since $([datetime]::fromfiletimeUTC($passwordsNotChangedSince))"  
  
$AccountsNoPasswordChangeSinceDate = Get-ADUser -filter { Enabled -eq $True } –Properties name,whenCreated,sAMAccountName,pwdLastSet,lastLogon,lastLogonTimeStamp -searchbase $searchbase | 
    where { $_.pwdLastSet -lt $passwordsNotChangedSince -and $_.pwdLastSet -ne 0 } |
    Select-Object name,whenCreated,sAMAccountName,@{Name="PasswordLastSet";Expression={[datetime]::FromFileTimeUTC($_.pwdLastSet) } }, `
        @{Name="lastLogon";Expression={[datetime]::FromFileTime($_.'lastLogon')}}, `
        @{Name="lastLogonTimeStamp";Expression={[datetime]::FromFileTime($_.'lastLogonTimeStamp')}}, `
        @{Name="DaysSinceLastLogon";Expression={ ([timespan]((Get-Date) - ([datetime]$_.lastLogonTimeStamp).AddYears(1600))).Days; }}

$AccountsNoPasswordChangeSinceDate.count
$AccountsNoPasswordChangeSinceDate | Export-Csv -NoTypeInformation -Path "D:\output\AccountsNoPasswordChangeSinceDate-20181231a.csv"
