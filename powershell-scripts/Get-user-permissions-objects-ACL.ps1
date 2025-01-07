# Import the Active Directory module
Import-Module ActiveDirectory

# Get the currently logged-on user's account
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Specify the domain context to search
$domain = Get-ADDomain
$searchBase = $domain.DistinguishedName

# Retrieve all objects in the domain
Write-Host "Retrieving all objects in the domain..." -ForegroundColor Yellow
$adObjects = Get-ADObject -Filter * -SearchBase $searchBase -Properties DistinguishedName

# Prepare a results array
$results = @()

Write-Host "Checking permissions on objects..." -ForegroundColor Yellow

# Iterate through each object to check permissions
foreach ($obj in $adObjects) {
    try {
        # Get the ACL for the current object
        $acl = Get-Acl "AD:$($obj.DistinguishedName)"
        
        # Filter ACL entries for the current user
        $userPermissions = $acl.Access | Where-Object {
            $_.IdentityReference -like "*$currentUser" -and ($_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll")
        }
        
        # If there are any matching permissions, add to results
        if ($userPermissions) {
            $results += [PSCustomObject]@{
                ObjectName         = $obj.Name
                DistinguishedName  = $obj.DistinguishedName
                RightsGranted      = ($userPermissions | ForEach-Object { $_.ActiveDirectoryRights }) -join ", "
            }
        }
    } catch {
        Write-Warning "Failed to retrieve ACL for object: $($obj.DistinguishedName)"
    }
}

# Output the results
if ($results.Count
