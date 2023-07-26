# Endpoint Security Assessment Kiddy
#Bypass Execution policy:
#Virtuvil
Set-ExecutionPolicy Bypass -Scope Process
# list users and their password update 
"User Accounts and Password Last Set:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt
Get-LocalUser | Select-Object Name, PasswordLastSet | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# check firewall status 
"Firewall Status:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# Check for USB status
"USB Status:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# If the value is "3", USB is enabled. If the value is "4", USB is blocked.
# Check RDP status
"RDP Status:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
Get-Service -Name TermService | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
# Check if admin logon is enabled
"Admin Logon Status:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
#(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AutoAdminLogon | Out-File -FilePath .\EndpointSecurityAssessment_output.txt # -Append
#"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
$value = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AutoAdminLogon
if ([string]::IsNullOrEmpty($value)) {
    "No registry value found" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
} else {
    $value | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
}
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# List all scheduled tasks
"Scheduled Tasks:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
Get-ScheduledTask | Select-Object -Property TaskName, Author, State | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# List all ready scheduled tasks
"Ready Scheduled Tasks:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
Get-ScheduledTask| Select-Object -Property TaskName, Author, State | Where-Object {$_.State -eq "Ready"} | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# Check files
"Exact Path Checks:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
$paths = @(
    "C:\Ck8GvVQ9E.README.txt",
    "$env:USERPROFILE\AppData\Local\Temp\LBB_PS1_obfuscated.ps",
    "$env:USERPROFILE\AppData\Local\Temp\LBB_PS1_obfuscated.ps1",
    "$env:USERPROFILE\Desktop\Ck8GvVQ9E.README.txt",
    "C:\ProgramData\DC28.tmp",
    "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Crashpad\settings.dat",
    "C:\Users\Ck8GvVQ9E.README.txt",
    "$env:USERPROFILE\AppData\Local\Temp\abf2hqvr.nfn.ps1",
    "$env:USERPROFILE\AppData\Local\Temp\ipqs5jmd.d5x.ps1"
)
$outputFilePath = ".\EndpointSecurityAssessment_output.txt "
$users = Get-ChildItem -Path "C:\Users" -Directory
foreach ($user in $users) {
    $userPath = Join-Path -Path $user.FullName -ChildPath "AppData\Local\Temp"
    if (Test-Path $userPath) {
        Write-Output "Checking paths for $($user.Name)..."
        foreach ($path in $paths) {
            $fullPath = Join-Path -Path $userPath -ChildPath $path.Substring(3)
            if (Test-Path $fullPath) {
                "$fullPath exists" | Out-File -FilePath $outputFilePath -Append
            } else {
                "$fullPath does not exist" | Out-File -FilePath $outputFilePath -Append
            }
        }
    } else {
        Write-Output "User $($user.Name) does not have a Temp folder."
    }
}
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# Directories to search for suspicious files
"File Checks:" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
$paths = @(
    "Ck8GvVQ9E.README.txt",
    "LBB_PS1_obfuscated.ps",
    "LBB_PS1_obfuscated.ps1",
    "Ck8GvVQ9E.README.txt",
    "DC28.tmp",
    "DC28.tmp",
    "Ck8GvVQ9E.README.txt",
    "abf2hqvr.nfn.ps1",
    "ipqs5jmd.d5x.ps1",
    "y1yhbnwj.1j2.psm1",
    "Ck8GvVQ9E.README.txt",
    "E1uGUHt.Ck8GvVQ9E",
    "AAAAAAAAAAAAAAAAAAAAAA",
    "BBBBBBBBBBBBBBBBBBBBBB",
    "{5D96BE62-B1A0-4CF6-8DBB-612ACD0A4C26}"
)
# Path to output file
$outputFilePath = ".\EndpointSecurityAssessment_output.txt"
# Search for suspicious files in every file on the C drive
Get-ChildItem -Path "C:\" -Recurse | ForEach-Object {
    if ($_.PSIsContainer) {
        # Ignore directories
        return
    }
    
    $filename = $_.Name
    if ($paths -contains $filename) {
        "$($_.FullName) exists" | Out-File -FilePath $outputFilePath -Append
    } else {
        "$($_.FullName) does not exist" | Out-File -FilePath $outputFilePath -Append
    }
}
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
# check password policy
"Local password policy: " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
net accounts | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
# Check for cortex
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
"Cortex Status: " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append
if (Get-Service -Name "Cortex" -ErrorAction SilentlyContinue) {
    "Cortex status" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
    Get-Service -Name cyserver | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
} else {
    "No cortex service found" | Out-File -FilePath .\EndpointSecurityAssessment_output.txt -Append
}
"  " | Out-File -FilePath .\EndpointSecurityAssessment_output.txt  -Append