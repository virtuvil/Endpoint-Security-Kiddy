**Endpoint Security Assessment Kiddy User Manual**

**Purpose:**
The "Endpoint Security Assessment Kiddy" script is designed to perform an assessment of endpoint security settings on a Windows computer. It checks various security-related configurations and looks for suspicious files that might indicate the presence of malware, particularly related to the "Lockbit" incident.

**Instructions:**
Open PowerShell with Administrator Privileges:
Before running the script, open PowerShell with administrator privileges. Right-click on the PowerShell icon and select "Run as Administrator."

**Set Execution Policy:**
The script requires execution policy bypass to run correctly. If your current PowerShell execution policy does not allow script execution, it will be temporarily bypassed for this session only. This is necessary for the script to run successfully.

**Running the Script:**
Copy and paste the entire script into the PowerShell window. Press Enter to execute each line of code.

**Viewing the Assessment Results:**
The script will generate an "EndpointSecurityAssessment_output.txt" file in the current directory where the script is executed. This file will contain the assessment results.

**Reviewing the Assessment Results:**
Open the "EndpointSecurityAssessment_output.txt" file with any text editor to view the assessment results. The results will include the following sections:
            
            User Accounts and Password Last Set: Lists the local user accounts on the system and their last password change date.
            
            Firewall Status: Indicates the status of the Windows Firewall (Enabled/Disabled).
            
            USB Status: Checks the status of USB storage (Enabled/Blocked).
            
            RDP Status: Checks the status of Remote Desktop Protocol (RDP) service.
            
            Admin Logon Status: Checks if automatic logon for the Administrator account is enabled or not.
            
            Scheduled Tasks: Lists all scheduled tasks on the system.
            
            Ready Scheduled Tasks: Lists scheduled tasks that are ready to run.
            
            Exact Path Checks: Checks for the existence of specific files in user-specific Temp directories.
            
            File Checks: Searches for suspicious files across the entire C drive.
            
            Local Password Policy: Displays the local password policy settings.
            
            Cortex Status: Checks the status of the Cortex service (if present).

**Interpreting Results:**

          For sections like "Firewall Status," "USB Status," and "RDP Status," look for "Enabled" to ensure security is enabled.
          
          In sections like "Exact Path Checks" and "File Checks," the script checks for the existence of specific files associated with the Lockbit incident. If any of these files are found, further investigation may be necessary.
          
          In the "Scheduled Tasks" sections, review the tasks to ensure they are legitimate and intended.
          
          The "Local Password Policy" section displays the current password policy settings.
          
          For "Cortex Status," if the service is found, it indicates that Cortex is present on the system.

**Action on Findings:**

          If any suspicious files are detected or unexpected security settings are found, further investigation and appropriate remediation actions should be taken.
          
          Review and analyze the findings in conjunction with your incident recovery team to understand the implications and take necessary actions to secure the system.

**Closing PowerShell:**

          Once you have reviewed the assessment results and taken necessary actions, close the PowerShell window.

**Note:** This script is a basic assessment tool and may not cover all possible security aspects. It is essential to consider it as part of a more comprehensive security analysis and incident recovery process.

Remember to exercise caution while using PowerShell scripts and ensure you have the necessary permissions and authorization to perform these assessments on the target system.
