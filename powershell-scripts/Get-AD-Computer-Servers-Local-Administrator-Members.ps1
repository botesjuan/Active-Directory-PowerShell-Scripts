# Output file
$outputFile = "D:\temp\Local_Admins_Report.csv"
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
    # $computerName = "PRD-SCCM01.ho.fosltd.co.za"
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
