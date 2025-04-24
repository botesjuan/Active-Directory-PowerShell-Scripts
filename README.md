# Active Directory PowerShell Scripts  

>Purpose of these PowerShell Scripts, is to get Notable Active Directory Accounts or high value objects:  
  
1. Potential weak accounts target by malicious actors with weak passwords
2. Notable AD User Accounts that have not change their passwords and did not logon since given date. - Dormant  
3. List all possible accounts with SPN values kerberoastable from Active Directory.  
4. High value AD Computers  
5. Get the current user running permissions for all objects ACL  
6. Password Spray single password against list of usernames.  

----  

## Potential Weak Targets  

>PowerShell active directory script to Identify accounts targeted by malicious actors that gain internal network access:
* Enabled accounts  
* Account created over 2 years ago  
* password last set older than 1 year  
* password never expires flag enabled  

>Remediation:  
* change to use strong complex passwords
* AD user Account with no recent logon history for last 6 months must be disabled
* Cleanup by removing all group membership and permissions  

```
Potential-weak-target-accounts.ps1
```  

----  

## Notable Dormant AD Users  

>PowerShell Script: `GET_ADUsers-Password_last_set_sinceDate1.ps1`  

>Provide number of days to calculate a date since password for user accounts in Active Directory was last changed and when last account logged on.

>Obtain the search base Distinguished name field "distinguishedName", value from active directory, using attribute editor in Active Directory Users and Computers MMC.

![AD Attribute Editor distinguishedName](/images/distinguishedName.png)

>Output from the PowerShell Script with random user account last logon date and last password set date to verify.  

![AD Account from data variable verify](/images/image003.png)

>This can be used during redteam or penetration test security assessment.  

----  

## Status of AD Group Members  

>Get the status of group members in group for their last logon, enabled, description, password last set dates:

```PowerShell
# Define the Active Directory group name
$GroupName = "Group Finance Users SG"

# Define the output CSV file path
$OutputCSV = "D:\Temp\FinanceSG_Members.csv"

# Import the Active Directory module (ensure RSAT is installed)
Import-Module ActiveDirectory

# Get members of the AD group
$Members = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }

# Retrieve user properties
$UserDetails = $Members | ForEach-Object {
    $User = Get-ADUser -Identity $_.SamAccountName -Properties SamAccountName, Description, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, LastLogon, LastLogonTimestamp
    
    # Convert LastLogon and LastLogonTimestamp to readable date format
    $LastLogonReadable = if ($User.LastLogon -gt 0) { [datetime]::FromFileTime($User.LastLogon) } else { $null }
    $LastLogonTimestampReadable = if ($User.LastLogonTimestamp -gt 0) { [datetime]::FromFileTime($User.LastLogonTimestamp) } else { $null }

    # Construct output object
    [PSCustomObject]@{
        SamAccountName      = $User.SamAccountName
        Description         = $User.Description
        Enabled             = $User.Enabled
        LastLogonDate       = $User.LastLogonDate
        PasswordLastSet     = $User.PasswordLastSet
        PasswordNeverExpires= $User.PasswordNeverExpires
        LastLogon           = $LastLogonReadable
        LastLogonTimestamp  = $LastLogonTimestampReadable
    }
}

# Export to CSV
$UserDetails | Export-Csv -Path $OutputCSV -NoTypeInformation

Write-Output "Export completed: $OutputCSV"
```  

----  

## Kerberoasting  

>PowerShell Script: `get-kerberoastable-user-info.ps1`  

>Get AD user accounts with SPN set and as result vulnerable to Kerberoasting attacks offline password cracking.  

```powershell
get-kerberoastable-user-info.ps1
Get-Content C:\temp\KerberoastingVulnerableAccounts.csv
```  

----  

## High Value Computes  

>Get list of AD computers where name contain string of possible crown jewels high value targets:  

```PowerShell
Get-ADComputer -Filter * -Properties LastLogonDate | 
    Where-Object { $_.Name -like "*hr*" } | 
    Select-Object Name, LastLogonDate | 
    Export-Csv -Path "D:\Support\servers\pay-servers-list-2025.csv" -NoTypeInformation -Force

```  

>List the results from CSV output: `Get-Content D:\Support\servers\pay-servers-list-2025.csv`  

>Get the local administrator members for each server AD computer that is active and enabled with last login in past 8 days:  

>Script: `Get-AD-Computer-Servers-Local-Administrator-Members.ps1`  

```PowerShell
# Output file
$outputFile = "D:\temp\Local_Administrators_on_servers_Report.csv"
$cutoffDate = (Get-Date).AddDays(-8)
$serverList = @()

# Step 1: Get server OS computers from AD
$serverList = Get-ADComputer -Filter {
    Enabled -eq $true -and
    OperatingSystem -like "*Server*"
} -Properties Name, OperatingSystem, LastLogonDate | Where-Object {
    $_.LastLogonDate -ne $null -and $_.LastLogonDate -ge $cutoffDate
}

$serverList.count

# Step 2: Create output structure
$result = @()

# Step 3: Loop through servers and query local administrators
foreach ($server in $serverList) {
    $computerName = $server.Name
	
    Write-Host "Checking local admins on: $computerName"

    try {
        $admins = Invoke-Command -ComputerName $computerName -ScriptBlock {
            try {
                $group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
                $members = @()
                $group.Members() | ForEach-Object {
                    $members += $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                }
                return $members
            } catch {
                return @("Error: $_")
            }
        } -ErrorAction Stop

        foreach ($admin in $admins) {
            $result += [PSCustomObject]@{
                ComputerName = $computerName
                Administrator = $admin
            }
        }
    } catch {
        $result += [PSCustomObject]@{
            ComputerName = $computerName
            Administrator = "Connection Failed: $_"
        }
    }
}

# Step 4: Export results to CSV
$result | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "Report saved to $outputFile"
```  

----  

## AD Account Activity  

>PowerShell Script: `AD-account-activity-status.ps1`  

>Providing an input file of user accounts to report on their, LastLogonTimestamp, if Account Enabled, When Password Last Set, If Password is set to Never Expires and value of Description field.  

----  

## Current user AD permissions on Objects  

>PowerShell Script: `Get-user-permissions-objects-ACL.ps1`  

>List the Active Directory objects that the currently logged-on user has write, modify, or full access permissions to edit.  

![acl-object-permissions.png](/images/acl-object-permissions.png)  

----  

## Password Policy & Spray  

>AD accounts with weak or old passwords are a security risk to an organization,  
>as their passwords may not comply to latest domain password policy and has been dormant.  
>Malicious actors finding these accounts can use it to gain read access to Active Directory.  

>Get the AD Password Policy:  

```PowerShell
# Specify the trusted domain name
$trustedDomain = "target.int"

# Get password policy details for the trusted domain
$passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $trustedDomain

# Display the password policy details
$passwordPolicy | Select-Object *
```  

![password-policy.png](/images/password-policy.png)  

>Attack using a password spray attack using nxc.  

```bash
nxc -t 1 smb domaincontroller.domain.internal -u userlist.txt -p password --continue-on-success
```  

>Above is nxc command to spray the password of password using list of possible Active Directory user accounts.  




