# Define input and output file paths
$inputFile = "D:\temp\usernames.txt"
$outputFile = "D:\temp\AD_UserReport.csv"

# Import user list from the input file
$usernames = Get-Content $inputFile

# Create a custom object to store the output information
$outputData = @()

# Loop through each username in the file
foreach ($username in $usernames) {
    # Get the AD user object for the current username
    $user = Get-ADUser -Identity $username -Properties LastLogonDate, Enabled, PasswordLastSet, Description, PasswordNeverExpires, LastLogon, LastLogonTimestamp

    if ($user) {
        # Convert LastLogon and LastLogonTimestamp from Integer8 format to DateTime
        $lastLogon = [DateTime]::FromFileTime($user.LastLogon)
        $lastLogonTimestamp = [DateTime]::FromFileTime($user.LastLogonTimestamp)

        # Create a custom object for each user's details
        $userInfo = [pscustomobject]@{
            Username              = $user.SamAccountName
            LastLogon             = $lastLogon
            LastLogonTimestamp    = $lastLogonTimestamp
            AccountEnabled        = $user.Enabled
            PasswordLastSet       = $user.PasswordLastSet
            PasswordNeverExpires  = $user.PasswordNeverExpires
            Description           = $user.Description
        }

        # Add the user info to the output array
        $outputData += $userInfo
    }
}

# Export the output data to a CSV file
$outputData | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Report generated successfully at $outputFile"
