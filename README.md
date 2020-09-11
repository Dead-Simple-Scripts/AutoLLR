# AutoLLR
Script to automate Linux live evidence collection

AutoLLR is a live Linux evidence collection script that gathers key artifacts important for Incident Response investigations. In addition to gathering artifacts AutoLLR does some low overhead post processing to produce refined results that analysts can look at immediately.

Results are divided into three (3) categories: 
1. System artifacts
- General system information including 
- Dumps all process ENVIRON data
- Collects bash histories
- SSH info
- and more 
    
2. Network artifacts 
- Different network connection pulls
 - Artifacts that record useful network information 
    
3. Triage searches
- Hidden files, directories, executables 
- Targeted directory checks
- Deleted binaries still running 
- Binaries running from temporary directories 
- Executables in interesting directories
- Assorted data spoliation searches 
- Assorted persistence searches 

Findings are hashed (MD5 SHA256) and archived upon completion.


Acknowledgments:
- Developers of Bambiraptor. Some of the code was structured after bambiraptor. 
- Sandfly Security. Some of the triage searches follow the Sandfly fast triage methodology 
    
    
Version 2.1 Updates - Bug fixes + setup command from Modules file combined into main script


Version 2.2 UPDATES: Fileless Linux Attack Detection
Dervived from Sandfly Security research: https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/

Processes with memfd executable
- Search logic: Any findings are suspicious
- Results: memfd_create_attack.txt
- Example results:
- lrwxrwxrwx 1 root root 0 Sep  1 20:00 /proc/14677/exe -> /memfd: (deleted)


Process cwd and exe agreement
Search logic: Each process environment has a COMM and CMDLINE file. Expect an actual binary name. In most instances, the binary reference is each should match. A mismatch is suspicious.
Results: memfd_create_attack.txt
Example results:
EXAMPLE (match): COMM: gpg-agent
EXAMPLE (match): CMDLINE: /usr/bin/gpg-agent--supervised
EXAMPLE (mismatch): COMM: 3
EXAMPLE (mismatch): CMDLINE: [kworker/0:pop]


Process CWD and EXE check
Search logic: search extracts the CWD and EXE value for each process. CWD values under root tend to be suspicious. EXE values that are deleted or running from non-standard directories are suspicious
Results: proc_cwd_exe_details.txt
Example results:
/proc/1196
lrwxrwxrwx   1 root root 0 Sep 11 15:27 cwd -> /root
lrwxrwxrwx   1 root root 0 Sep 11 15:23 exe -> 'memfd: (deleted)


Process map details with memfd references
Search logic: Search greps only for entries with 'memfd’. The file /proc/<PID>/maps will contain process mappings for a binary. This will show the binary name, plus other library files it is using when it runs. Normally the first part of this file contains a reference to the actual binary that is running (e.g. /usr/bin/vi). References to /memfd: (deleted) may be suspicious.
Results: proc_memfd_map.txt


Process environ ssh details
Search logic: Commands started over SSH will often show the client IP address that did it in this artifact.
Results:  proc_environ_ssh.txt


