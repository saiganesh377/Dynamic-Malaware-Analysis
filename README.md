# Dynamic-Malaware-Analysis
Findings and inferences of dynamic malware analysis of a malware sample inside a virtual machine.
## Tools used:
•	Wireshark <br />
•	Process Monitor <br />
•	Process hacker <br />
•	Regshot <br />
•	Windows Task Scheduler <br />
•	HashMyFiles <br />
## Downloading the Malware sample and unzipping:
The malware sample is downloaded from MalwareBazaar. It comes as a zip file which can be extracted by entering the privacy password. It is typically a SHA256 encrypted file. Once everything is set, we can run the malware as administrator to analyze its activities during its runtime.
## Process Activities:
While using extensive process capturing tools like Process Monitor and process hacker, we will encounter a lot of logs and activities, so the first step we need to do is to detect the processes belonging to the malware.
![proctree](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/87233da3-594d-4a75-8c0f-531d5eea6c14)

Malware’s child processes can be self-terminating and therefore we need a tool that will be able to capture the entire process tree of any process and not only the process that momentarily executes.
Therefore, we use process monitor. The process tree provided by Procmon completes this shortcoming of Process Hacker, as it also includes terminated processes.
![proctree1](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/16980473-2e31-45b2-a423-54d2a5b806c0)

When we go over the the image above, we see that the malware 722ef401e5cbb067c5c33faa402774d3c75ef08e0c8cc4d7e66a9cfa53684088.exe runs the tool called “schtasks.exe” belonging to Windows Task Scheduler (PID 1460) and then runs its own malware again.
Before moving on to other activities, let's examine the schtasks.exe process. Schtasks.exe is a tool that enables the Task Scheduler to be used via the command interface in the Windows operating system. Attackers ensure persistency by adding their own malware to scheduled tasks with the help of Task Scheduler.
In order to see what kind of scheduled task the attacker added, we must click on the "schtasks.exe" (1460 PID) in the process tree of procmon and examine its details.
![proctree2](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/4a9801d2-6c33-4f6a-a444-e8e733840570)

When we examine the command-line arguments, we see that a scheduled task named "Updates\VbxFiQYCyFDgGL" has been created. 
![tsksc](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/4b177f16-49e8-4ef4-90b1-b672ab396cea)

On the Trigger tab, the situations in which the malware runs are designed by the attacker is seen. As it can be seen on the screenshot above this scheduled task will run at log on. 
You can see what action will run on the Actions tab. You can see on the above screenshot that the malicious software named “VbxFiQYCyFDgGL.exe” prepared by the attacker will run when this scheduled task runs.
This is how we have detected the scheduled task that the attacker added.
![tsksc1](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/bc83f459-fa67-4924-bf74-ea444ab40db7)

## Network Activities:
![wireshark](https://github.com/saiganesh377/Dynamic-Malaware-Analysis/assets/73426769/c11d0de2-f3e9-4eab-b7f0-f5b43e9343e0)

Here we captured the packet, typically the IP requests made on our machine. Here we see a particularly peculiar DNS request being sent to a fishy domain URL “5gw4d.xyz”

## File Activities:
When we examine the file activities further, we see that the malware reads the files to steal information from applications such as Firefox, Chome, Thunderbird. We have determined that the malware we have is information stealer. We can compare the replicated files with the original malware using HashMyfiles application to unmask the malware.
 
## Inference Report:
•	the malware has copied itself to the "C:\Users\Username\AppData\Roaming\" directory with the name "VbxFiQYCyFDgGL.exe", <br />
•	has used Task Scheduler to ensure persistence, <br />
•	has enabled its own malicious application to run at every logon by creating a scheduled task with the name "VbxFiQYCyFDgGL" <br />
•	communicates with the command & control server, <br />
the command control address is “5gw4d[.]xyz/PL341/index.php” and it communicates over the HTTP protocol, <br />
•	discovers the applications installed in the system with the help of the key under the "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" registry key, <br />
•	steals sensitive data from applications such as Chrome, Firefox, Thunderbird. <br />







