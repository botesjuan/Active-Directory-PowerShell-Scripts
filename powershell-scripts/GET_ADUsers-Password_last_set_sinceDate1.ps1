# Nyumber of days in past to check from date before if account last logon and password last set date is less
$Days = 365
$searchdate = (Get-Date).Adddays(-($Days))
$searchdate

$searchbase = "DC=childdomain,DC=parentdomain,DC=co,DC=za"

$DormantLogons = Get-ADUser -Filter {(Enabled -eq $True) -and (LastLogonTimeStamp -lt $searchdate)} -Properties * -searchbase $searchbase |
    Select Name,LastLogonDate,Enabled,SamAccountName,@{Name="PasswordLastSet";Expression={[datetime]::FromFileTimeUTC($_.pwdLastSet)}}

# could have done oneliner - argh but i like peanuts
$NotableAccounts = $DormantLogons | where { $_.PasswordLastSet -lt $searchdate -and $_.PasswordLastSet -ne 0 }

# number of accounts that last logon date is less than date in past
$DormantLogons.count
# number of AD accounts that password last set is less than date in past
$NotableAccounts.count

# random account to check because the answer to the universe is 42
$NotableAccounts[42]
$NotableAccounts | Export-Csv D:\Scripts\output\Inactive_ADuserAccounts.csv -NoTypeInformation
 
