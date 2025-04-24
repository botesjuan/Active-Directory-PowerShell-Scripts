$Users_Do_not_require_pwd = Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties Name,Description,SamAccountName,GivenName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,LastLogon,LastLogonTimestamp,PasswordNotRequired | Where-Object { $_.enabled -eq $true }
$Users_Do_not_require_pwd.count

# Retrieve user properties
$UserDetails = $Users_Do_not_require_pwd | ForEach-Object {
    $User = Get-ADUser -Identity $_.SamAccountName -Properties Name,Description,SamAccountName,GivenName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,LastLogon,LastLogonTimestamp,PasswordNotRequired
    
    # Convert LastLogon and LastLogonTimestamp to readable date format
    $LastLogonReadable = if ($User.LastLogon -gt 0) { [datetime]::FromFileTime($User.LastLogon) } else { $null }
    $LastLogonTimestampReadable = if ($User.LastLogonTimestamp -gt 0) { [datetime]::FromFileTime($User.LastLogonTimestamp) } else { $null }

    # Construct output object
    [PSCustomObject]@{
        SamAccountName      = $User.SamAccountName
        Name                = $User.Name
        Description         = $User.Description
        GivenName           = $User.GivenName
        Enabled             = $User.Enabled
        LastLogonDate       = $User.LastLogonDate
        PasswordLastSet     = $User.PasswordLastSet
        PasswordNeverExpires= $User.PasswordNeverExpires
        LastLogon           = $LastLogonReadable
        LastLogonTimestamp  = $LastLogonTimestampReadable
        PasswordNotRequired = $User.PasswordNotRequired
    }
}


$UserDetails | Export-Csv -Path "D:\temp\Users_do_not_require_Passwords.csv" -NoTypeInformation

