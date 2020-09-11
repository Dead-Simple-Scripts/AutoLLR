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


Version 2.2 Updates: Fileless Linux attack detection
Dervived from Sandfly Security research: https://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
- Processes with memfd executable
- Process cwd and exe agreement
- Process CWD and EXE check
- Process map details with memfd references
- Process environ ssh details



