# Active Directory PowerShell Scripts  

>Purpose of these PowerShell Scripts, is to get Notable Active Directory Accounts or high value objects:  
  
1. Extract a list of notable AD User Accounts that have not change their passwords and did not logon since given date. - Dormant  
2. List all possible accounts with SPN values kerberoastable from Active Directory.  
3. High value AD Computers  
4. Get the current user running permissions for all objects ACL  
5. Password Spray single password against list of usernames.  

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




