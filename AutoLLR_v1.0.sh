#!/bin/bash
echo ""
echo "********************************"
echo "*           AutoLLR            *"
echo "*  Linux Live Response script  *"
echo "*          Version 1           *"
echo "*                              *"
echo "*           by Michael Leclair *"
echo "********************************"
echo ""
echo "Script to autorun common Linux live response commands"
echo "Usage: sudo ./AutoLLR.sh"
read -p "Press enter to continue"
#
#INITIAL SETUP
ScriptStart=$(date +%s)
lrcbuildname="AutoLLR_v1.0"
scriptname=`basename "$0"`
# Directory script runs in
directorywherescriptrunsfrom=$(pwd)
runningfromexternal="no"
cname=$(hostname -s)
ts=$(date +%Y%m%d_%H%M%S)
computername=$cname\_$ts
mkdir -p $computername
mkdir -p $computername/LiveResponseData/SystemInfo
mkdir -p $computername/LiveResponseData/NetworkInfo
mkdir -p $computername/LiveResponseData/TriageSearches
mkdir -p $computername/LiveResponseData/Logs
mkdir -p $computername/LiveResponseData/Logs/var
mkdir -p $computername/LiveResponseData/Logs/cron
mkdir -p $computername/LiveResponseData/Logs/environ
printf "OS Type: nix\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Computername: $cname\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Time stamp: $ts\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Live Response Collection version: $lrcbuildname\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Live Response Collection script run: $scriptname\n\n" >> "$computername/$computername""_Processing_Details.txt"

exec 2>/dev/null

echo ""
echo "****************************"
echo "*  AutoLLR script started  *"
echo "****************************"
echo ""
# >>>>>>>>>> THINGS TO RUN FIRST <<<<<<<<<<
# get root bash history
echo "get root bash_history
cat /root/.bash_history
**********" >> $computername/LiveResponseData/SystemInfo/root-bash_History.txt
cat /root/.bash_history >> $computername/LiveResponseData/SystemInfo/root-bash_History.txt
echo "cat /root/.bash_history"

# dump process environments
mkdir -p $computername/LiveResponseData/Logs/environ
echo "dumping process environments"
for i in `find /. -name 'environ'`; do
  new=`echo $i|nawk -F"/" '{split($NF,a,".");print "'$computername'/LiveResponseData/Logs/environ/"a[1]"_"$(NF-1)"."a[2]}'`
  cp $i $new
done

for file in $computername/LiveResponseData/Logs/environ/*; do
  strings "$file" > "${file%}.strings.txt"
done

# >>>>>>>>>> LOGS <<<<<<<<<<
echo "cp /var/log/*.log*"
cp /var/log/*.log* $computername/LiveResponseData/Logs/var
echo "cp -r /etc/cron*"
cp -r /etc/cron* $computername/LiveResponseData/Logs/cron


# >>>>>>>>>> GENERAL SYSTEM INFORMATION <<<<<<<<<<
echo "date
**********" >> $computername/LiveResponseData/SystemInfo/date.txt
date >> $computername/LiveResponseData/SystemInfo/date.txt
echo "date"
#
echo "hostname
**********" >> $computername/LiveResponseData/SystemInfo/hostname.txt
hostname >> $computername/LiveResponseData/SystemInfo/hostname.txt
echo "hostname"
#
echo "logged in users
who
**********" >> $computername/LiveResponseData/SystemInfo/Logged_In_Users.txt
who >> $computername/LiveResponseData/SystemInfo/Logged_In_Users.txt
echo "who"
#
echo "List of Running Processes
ps aux --forest
**********" >> $computername/LiveResponseData/SystemInfo/List_of_Running_Processes.txt
ps aux --forest >> $computername/LiveResponseData/SystemInfo/List_of_Running_Processes.txt
echo "ps aux --forest"
#
echo "Process tree and arguments
pstree -ah
**********" >> $computername/LiveResponseData/SystemInfo/Process_tree_and_arguments.txt
pstree -ah >> $computername/LiveResponseData/SystemInfo/Process_tree_and_arguments.txt
echo "pstree -ah"
#
echo "Mounted items
mount
**********" >> $computername/LiveResponseData/SystemInfo/Mounted_items.txt
mount >> $computername/LiveResponseData/SystemInfo/Mounted_items.txt
echo "mount"
#
echo "diskutil
***********" >> $computername/LiveResponseData/SystemInfo/Disk_utility.txt
diskutil list >> $computername/LiveResponseData/SystemInfo/Disk_utility.txt
echo "diskutil"
#
echo "Loaded Kernel Extensions
kextstat -l
**********" >> $computername/LiveResponseData/SystemInfo/Loaded_Kernel_Extensions.txt
kextstat -l >> $computername/LiveResponseData/SystemInfo/Loaded_Kernel_Extensions.txt
echo "kextstat -l"
#
echo "uptime
**********" >> $computername/LiveResponseData/SystemInfo/System_uptime.txt
uptime >> $computername/LiveResponseData/SystemInfo/System_uptime.txt
echo "uptime"
#
echo "System environment
uname -a
**********" >> $computername/LiveResponseData/SystemInfo/System_environment.txt
uname -a >> $computername/LiveResponseData/SystemInfo/System_environment.txt
echo "uname -a"
#
echo "System environment details
prinenv
**********" >> $computername/LiveResponseData/SystemInfo/System_environment_details.txt
printenv >> $computername/LiveResponseData/SystemInfo/System_environment_details.txt
echo "prinenv"
#
echo "OS kernel version
cat /proc/version
**********" /proc/version >> $computername/LiveResponseData/SystemInfo/OS_kernel_version.txt
cat /proc/version >> $computername/LiveResponseData/SystemInfo/OS_kernel_version.txt
echo "cat /proc/version"
#
echo "process memory usage
top -n 1 -b
**********" >> $computername/LiveResponseData/SystemInfo/Process_memory_usage.txt
top -n 1 -b >> $computername/LiveResponseData/SystemInfo/Process_memory_usage.txt
echo "top -n 1 -b"
#
echo "load averages
cat /proc/loadavg
**********" >> $computername/LiveResponseData/SystemInfo/loadavg.txt
cat /proc/loadavg >> $computername/LiveResponseData/SystemInfo/loadavg.txt
echo "cat /proc/loadavg"
#
echo "dmesg
command on most Unix-like operating systems that prints the message buffer of the kernel. The output of this command typically contains the messages produced by the device drivers.
dmesg
***********" >> $computername/LiveResponseData/SystemInfo/dmesg.txt
dmesg >> $computername/LiveResponseData/SystemInfo/dmesg.txt
echo "dmesg"
#
echo "meminfo
cat /proc/meminfo
************" >> $computername/LiveResponseData/SystemInfo/meminfo.txt
cat /proc/meminfo >> $computername/LiveResponseData/SystemInfo/meminfo.txt
echo "meminfo"
#
echo "vmstat
cat /proc/vmstat
***********" >> $computername/LiveResponseData/SystemInfo/vmstat.txt
cat /proc/vmstat >> $computername/LiveResponseData/SystemInfo/vmstat.txt
echo "vmstat"
#
echo "mount points
cat /proc/mounts
**********" >> $computername/LiveResponseData/SystemInfo/mounts.txt
cat /proc/mounts >> $computername/LiveResponseData/SystemInfo/mounts.txt
echo "cat /proc/mounts"
#
echo "Partitions
cat /proc/partitions
**********" >> $computername/LiveResponseData/SystemInfo/partitions.txt
cat /proc/partitions >> $computername/LiveResponseData/SystemInfo/partitions.txt
echo "cat /proc/partitions"
#
echo "swap partitions
cat /proc/swaps
**********" >> $computername/LiveResponseData/SystemInfo/swap_partitions.txt
cat /proc/swaps >> $computername/LiveResponseData/SystemInfo/swap_partitions.txt
echo "cat /proc/swaps"
#
echo "Disk information
df -k
**********" >> $computername/LiveResponseData/SystemInfo/disk_info.txt
df -k >> $computername/LiveResponseData/SystemInfo/disk_info.txt
echo "df -k"
#
echo "running processes
ps -T
**********" >> $computername/LiveResponseData/SystemInfo/running_proceeses.txt
ps -T >> $computername/LiveResponseData/SystemInfo/running_proceeses.txt
echo "ps -T"
#
echo "lsof
***********" >> $computername/LiveResponseData/SystemInfo/lsof.txt
lsof >> $computername/LiveResponseData/SystemInfo/lsof.txt
echo "lsof"
#
echo "Boot image
cat /proc/cmdline
**********" >> $computername/LiveResponseData/SystemInfo/boot_image.txt
cat /proc/cmdline >> $computername/LiveResponseData/SystemInfo/boot_image.txt
echo "cat /proc/cmdline"
#
echo "modules
cat /proc/modules
**********" >> $computername/LiveResponseData/SystemInfo/proc_modules.txt
cat /proc/modules >> $computername/LiveResponseData/SystemInfo/proc_modules.txt
echo "cat proc/modules"
#
# sysctl -A >> $computername/LiveResponseData/SystemInfo/sysctl-A.txt
# echo "sysctl -A"
#
echo "interrupts
cat /proc/interrupts
***********" >> $computername/LiveResponseData/SystemInfo/proc_interrupts
cat /proc/interrupts >> $computername/LiveResponseData/SystemInfo/proc_interrupts
echo "cat proc/interrupts"
#
echo "Process devices
cat /proc/devices
**********" >> $computername/LiveResponseData/SystemInfo/proc_devices
cat /proc/devices >> $computername/LiveResponseData/SystemInfo/proc_devices
echo "cat proc/devices"
#
echo " io ports
cat /proc/ioports
**********" >> $computername/LiveResponseData/SystemInfo/proc_ioports
cat /proc/ioports >> $computername/LiveResponseData/SystemInfo/proc_ioports
echo "cat proc/ioports"
#
echo "Processes
lsof -n -P -V
***********" >> $computername/LiveResponseData/SystemInfo/processes.txt
lsof -n -P -V >> $computername/LiveResponseData/SystemInfo/processes.txt
echo "lsof -n -P -V"
#
echo "Running services
service --status-all | grep +
**********" >> $computername/LiveResponseData/SystemInfo/Running_services.txt
service --status-all | grep + >> $computername/LiveResponseData/SystemInfo/Running_services.txt
echo "service --status-all | grep +"
#
echo "loaded modules
lsmod | head
**********" >> $computername/LiveResponseData/SystemInfo/Loaded_modules.txt
lsmod | head >> $computername/LiveResponseData/SystemInfo/Loaded_modules.txt
echo "lsmod | head"
#
echo "last logins
last
**********" >> $computername/LiveResponseData/SystemInfo/Last_logins.txt
last >> $computername/LiveResponseData/SystemInfo/Last_logins.txt
echo "last"
#
echo "cat /etc/passwd
**********" >> $computername/LiveResponseData/SystemInfo/passwd.txt
cat /etc/passwd >> $computername/LiveResponseData/SystemInfo/passwd.txt
echo "cat /etc/passwd"
#
echo "cat /etc/group
**********" >> $computername/LiveResponseData/SystemInfo/group.txt
cat /etc/group >> $computername/LiveResponseData/SystemInfo/group.txt
echo "cat /etc/group"
#
echo "lastlog
**********" >> $computername/LiveResponseData/SystemInfo/Last_login_per_user.txt
lastlog >> $computername/LiveResponseData/SystemInfo/Last_login_per_user.txt
echo "lastlog"
#
echo "whoami
**********" >> $computername/LiveResponseData/SystemInfo/whoami.txt
whoami >> $computername/LiveResponseData/SystemInfo/whoami.txt
echo "whoami"
#
echo "logname
**********" >> $computername/LiveResponseData/SystemInfo/logname.txt
logname >> $computername/LiveResponseData/SystemInfo/logname.txt
echo "logname"
#
echo "id
**********" >> $computername/LiveResponseData/SystemInfo/id.txt
id >> $computername/LiveResponseData/SystemInfo/id.txt
echo "id"
#
echo "getting bash histories from /home/<users>"
for i in `ls /home/`
do
	cat /home/$i/.bash_history >> $computername/LiveResponseData/SystemInfo/home-$i-bash_History.txt
	echo "cat $i bash_history"
done
#
#Check if SELINUX is installed
echo "Check if SELINUX is installed
sestatus
**********" >> $computername/LiveResponseData/SystemInfo/selinux_status.txt
selinux >> $computername/LiveResponseData/SystemInfo/selinux_status.txt
echo "sestatus"

echo "SSH configuration details
cat /etc/ssh/sshd.config
**********" >> $computername/LiveResponseData/SystemInfo/sshd_config.txt
cat /etc/ssh/sshd.config >> $computername/LiveResponseData/SystemInfo/sshd_config.txt
echo "cat /etc/ssh/sshd.config"

echo "Global configuration check: DNS name servers. Check for overrides
cat /etc/resolv.conf
**********" >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
cat /etc/resolv.conf >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
echo "cat /etc/resolv.conf"

echo "Global configuration check: Check for suspicious host file alterations.
Example: User directed to 1.1.1.1 when trying to go to google.com
1.1.1.1    www.google.com
cat /etc/hosts
**********" >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
cat /etc/hosts >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
echo "cat /etc/hosts"


# >>>>>>>>>> GENERAL NETWORK INFORMATION <<<<<<<<<<

echo "netstat -anp
**********" >> $computername/LiveResponseData/NetworkInfo/netstat_current_connections.txt
netstat -anp >> $computername/LiveResponseData/NetworkInfo/netstat_current_connections.txt
echo "netstat -anp"
#
echo "PROMISC adapters
ip link | grep PROMISC
**********" >> $computername/LiveResponseData/NetworkInfo/PROMISC_adapter_check.txt
ip link | grep PROMISC >> $computername/LiveResponseData/NetworkInfo/PROMISC_adapter_check.txt
echo "ip link | grep PROMISC"
#
echo "socket statistics
ss
**********" >> $computername/LiveResponseData/NetworkInfo/socket_statistics.txt
ss >> $computername/LiveResponseData/NetworkInfo/socket_statistics.txt
echo "ss"
#
echo "network connections
lsof -i -n -P
**********" >> $computername/LiveResponseData/NetworkInfo/network_connections_1.txt
lsof -i -n -P >> $computername/LiveResponseData/NetworkInfo/network_connections_1.txt
echo "lsof -i -n -P"
#
echo "routing table
netstat -rn
**********" >> $computername/LiveResponseData/NetworkInfo/Routing_table.txt
netstat -rn >> $computername/LiveResponseData/NetworkInfo/Routing_table.txt
echo "netstat -rn"
#
echo "arp table
netstat -rn
**********" >> $computername/LiveResponseData/NetworkInfo/ARP_table.txt
arp -an >> $computername/LiveResponseData/NetworkInfo/ARP_table.txt
echo "arp -an"
#
echo "network interface information
ifconfig -a
**********" >> $computername/LiveResponseData/NetworkInfo/Network_interface_info.txt
ifconfig -a >> $computername/LiveResponseData/NetworkInfo/Network_interface_info.txt
echo "ifconfig -a"
#
echo "hosts allowed
cat /etc/hosts.allow
**********" >> $computername/LiveResponseData/NetworkInfo/Hosts_allow.txt
cat /etc/hosts.allow >> $computername/LiveResponseData/NetworkInfo/Hosts_allow.txt
echo "cat /etc/hosts.allow"
#
echo "hosts deny
cat /etc/hosts.deny
**********" >> $computername/LiveResponseData/NetworkInfo/Hosts_deny.txt
cat /etc/hosts.deny >> $computername/LiveResponseData/NetworkInfo/Hosts_deny.txt
echo "cat /etc/hosts.deny"
#
echo "cat /proc/net/arp
**********" >> $computername/LiveResponseData/NetworkInfo/proc_net_arp.txt
cat /proc/net/arp >> $computername/LiveResponseData/NetworkInfo/proc_net_arp.txt
echo "cat /proc/net/arp"
#
echo "netstat -antp
**********" >> $computername/LiveResponseData/NetworkInfo/netstat-programs.txt
netstat -antp >> $computername/LiveResponseData/NetworkInfo/netstat-programs.txt
echo "netstat -antp"
#
echo "netstat -anp
**********" >> $computername/LiveResponseData/NetworkInfo/netstat-ports.txt
netstat -anp >> $computername/LiveResponseData/NetworkInfo/netstat-ports.txt
echo "netstat -anp"
#
echo "echo ifconfig -s
**********" >> $computername/LiveResponseData/NetworkInfo/interface_errors.txt
echo ifconfig -s >> $computername/LiveResponseData/NetworkInfo/interface_errors.txt
echo "ifconfig -s"
#
echo "lsof -P -n -i -V
**********" >> $computername/LiveResponseData/NetworkInfo/processes_connections.txt
lsof -P -n -i -V >> $computername/LiveResponseData/NetworkInfo/processes_connections.txt
echo "lsof -P -n -i -V"



# >>>>>>>>>> TRIAGE SEARCHES <<<<<<<<<<
#
echo "Find hidden files
find / -name \".*\" -ls
**********" >> $computername/LiveResponseData/TriageSearches/hiddenfiles.txt
find / -name ".*" -ls >> $computername/LiveResponseData/TriageSearches/hiddenfiles.txt
echo "find / -name \".*\" -ls"

# find hidden directories
echo "find hidden directories
EXAMPLE:
/bin/. .
/dev/.blKb
/dev/shm/. .
find / -type d -name \".*\"
**********" >> $computername/LiveResponseData/TriageSearches/hidden_dirs.txt
find / -type d -name ".*" >> $computername/LiveResponseData/TriageSearches/hidden_dirs.txt
echo "find / -type d -name \".*\”"

# find hidden executables everywhere
echo "find hidden executables, more focused hidden file search
EXAMPLE: /var/tmp/.ICE-unix/.db: ELF 64-bit ... stripped
find / -name \".*\" -exec file -p '{}' \; | grep ELF
**********" >> $computername/LiveResponseData/TriageSearches/hidden_binaries_everywhere.txt
find / -name ".*" -exec file -p '{}' \; | grep ELF >> $computername/LiveResponseData/TriageSearches/hidden_binaries_everywhere.txt
echo "find / -name ".*" -exec file -p '{}' \; | grep ELF"

# bin directory listing, look for odd names
echo "bin directory listing, look for odd names
EXAMPLE:
drwxr-xr-x 2 root root 4096 Jul 25 21:45  << space
drwxr-xr-x 2 root root 4096 Sep 7 09:52 . << dot
drwxr-xr-x 10 root root 12288 Sep 7 09:52 . << space dot
drwxr-xr-x 2 root root 4096 Mar 25 2017 .  << dot space
drwxr-xr-x 2 root root 4096 Mar 25 2017 . . << space dot space
drwxr-xr-x 24 root root 4096 Oct 11 04:01 ..
drwxr-xr-x 2 root root 4096 Jun 4 01:56 ..    << dot dot space
drwxr-xr-x 2 root root 4096 Jun 4 02:25 ...  << 3 dots
drwxr-xr-x 2 root root 4096 Jun 7 00:46 ..%  << special characters
ls -lap /bin
**********" >> $computername/LiveResponseData/TriageSearches/bin_dir_list.txt
ls -lap /bin >> $computername/LiveResponseData/TriageSearches/bin_dir_list.txt
echo "ls -lap /bin"

# deleted binaries still running
echo "
EXAMPLE: lrwxrwxrwx 1 root root 0 Nov 13 07:39 /proc/10580/exe -> /usr/bin/perl (deleted)
Why is a binary still running if deleted?
ls -alR /proc/*/exe | grep deleted
**********" >> $computername/LiveResponseData/TriageSearches/deleted_binaries_still_running.txt
ls -alR /proc/*/exe | grep deleted >> $computername/LiveResponseData/TriageSearches/deleted_binaries_still_running.txt
echo "ls -alR /proc/*/exe | grep deleted"

# binaries running from temp directories
echo "binaries running from temp directories, always suspicious
EXAMPLE: lrwxrwxrwx 1 root root 0 Nov 14 02:07 /proc/10580/cwd -> /tmp
ls -alR /proc/*/exe | grep tmp
**********" >> $computername/LiveResponseData/TriageSearches/binaries_running_from_temp.txt
ls -alR /proc/*/exe | grep tmp >> $computername/LiveResponseData/TriageSearches/binaries_running_from_temp.txt
echo "ls -alR /proc/*/exe | grep tmp"

# tmp diectory files - check for notable names
echo "tmp diectory files - check for notable names
sometimes remnant attacker files get left behind here
EXAMPLE: -rw-r--r-- 1 root root 2304 Sep 5 00:12 utmp.bak
^^ left behind from a log cleaner
ls -al /tmp
**********" >> $computername/LiveResponseData/TriageSearches/tmp_dir_files.txt
ls -al /tmp >> $computername/LiveResponseData/TriageSearches/tmp_dir_files.txt
echo "ls -al /tmp"

# identify executables in tmp directory
echo "identify executables in tmp directory
find /tmp -type f -exec file -p '{}' \; | grep ELF
**********" >> $computername/LiveResponseData/TriageSearches/tmpdir_exec_files.txt
find /tmp -type f -exec file -p '{}' \; | grep ELF >> $computername/LiveResponseData/TriageSearches/tmpdir_exec_files.txt
echo "find /tmp -type f -exec file -p '{}' \; | grep ELF"

# all tmp files with file type identification, better version
echo "all tmp files with file type identification, better version
EXAMPLE: EXAMPLE: /tmp/.ICE-unix/.db: ELF 64-bit ... stripped
find /tmp -type f -exec file -p '{}' \;
**********" >> $computername/LiveResponseData/TriageSearches/tmp_dir_files_better.txt
find /tmp -type f -exec file -p '{}' \; >> $computername/LiveResponseData/TriageSearches/tmpdir_files_better.txt
echo "find /tmp -type f -exec file -p '{}' \;"

# find named pipes
echo "find named pipes
EXAMPLE: /tmp/f
find / -type p
**********" >> $computername/LiveResponseData/TriageSearches/named_pipes.txt
find / -type p >> $computername/LiveResponseData/TriageSearches/named_pipes.txt
echo "find / -type p"

# covering tracks: check for zero size logs
echo "covering tracks: check for zero size logs
ls -al /var/log/*
**********" >> $computername/LiveResponseData/TriageSearches/log_listing.txt
ls -al /var/log/* >> $computername/LiveResponseData/TriageSearches/log_listing.txt
echo "ls -al /var/log/*"

# covering tracks: find logs with binary in them
echo "covering tracks: find logs with binary in them
grep [[:cntrl:]] /var/log/*.log
**********" >> $computername/LiveResponseData/TriageSearches/logs_with_binary.txt
grep [[:cntrl:]] /var/log/*.log >> $computername/LiveResponseData/TriageSearches/logs_with_binary.txt
echo "grep [[:cntrl:]] /var/log/*.log"

# persistence check: find immutable files, immutable binary are suspicious << medium expense
echo "find immutable files, any immutable binary is suspicious
EXAMPLE:
----i---------e--- /tmp/.t
----i---------e--- /bin/pss
lsattr / -R  | grep \"\----i\"
**********" >> $computername/LiveResponseData/TriageSearches/immutable_files.txt
lsattr / -R  | grep "\----i" >> $computername/LiveResponseData/TriageSearches/immutable_files.txt
echo "lsattr / -R  | grep \"\----i\""

# persistence check: find rhost files
echo "find rhost files
The .rhosts file is the user equivalent of the /etc/hosts.equiv file. It contains a list of host-user combinations, rather than hosts in general. If a host-user combination is listed in this file, the specified user is granted permission to log in remotely from the specified host without having to supply a password.
find / -name .rhosts -print
**********" >> $computername/LiveResponseData/TriageSearches/rhost_files.txt
find / -name .rhosts -print >> $computername/LiveResponseData/TriageSearches/rhost_files.txt
echo "find / -name .rhosts -print"

# persistence check: find files/dirs with no user/group name:
echo "persistence check: find files/dirs with no user/group name
find / \( -nouser -o -nogroup \) -exec ls -lg {} \;
**********" >> $computername/LiveResponseData/TriageSearches/no_usrgrp_name.txt
find / \( -nouser -o -nogroup \) -exec ls -lg {} \; >> $computername/LiveResponseData/TriageSearches/no_usrgrp_name.txt
echo "find / \( -nouser -o -nogroup \) -exec ls -lg {} \;"

# persistence check: find SUID/SGID files
echo "persistence check: find SUID/SGID files
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
**********" >> $computername/LiveResponseData/TriageSearches/suid_sgid_files.txt
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; >> $computername/LiveResponseData/TriageSearches/suid_sgid_files.txt
echo "find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;"

# persistence check: find history files linked to /dev/null
echo "persistence check: find history files linked to /dev/null
EXAMPLE: lrwxrwxrwx 1 www www 9 Nov 13 00:23 .bash_history -> /dev/null
ls -alR / | grep .*history | grep null
**********" >> $computername/LiveResponseData/TriageSearches/use_hstfile_null.txt
ls -alR / | grep .*history | grep null >> $computername/LiveResponseData/TriageSearches/use_hstfile_null.txt
echo "ls -alR / | grep .*history | grep null"

# persistence check: check user history files for creation date\time outliers or any with zero bytes
echo "persistence check: check user history files for creation date\time outliers or any with zero bytes
ls -alR / | grep .*history
**********" >> $computername/LiveResponseData/TriageSearches/usr_hstfile_meta.txt
ls -alR / | grep .*history >> $computername/LiveResponseData/TriageSearches/usr_hstfile_meta.txt
echo "ls -alR / | grep .*history"

# persistence check: quick listing of all user history files for reference
echo "persistence check: quick listing of all user history files for reference
find / -name .*history
**********" >> $computername/LiveResponseData/TriageSearches/usr_hstfiles_quicklisting.txt
find / -name .*history >> $computername/LiveResponseData/TriageSearches/usr_hstfiles_quicklisting.txt
echo "find / -name .*history"

# persistence check: find all ssh authorized_keys files
echo "persistence check: find all ssh authorized_keys files
Do you recognize all the users that should have ssh keys?
EXAMPLE:
/root/.ssh/authorized_keys
/bin/.ssh/authorized_keys << suspicious
/home/jsmith/.ssh/authorized_keys
/home/www/.ssh/authorized_keys  << suspicious
find / -name authorized_keys
**********" >> $computername/LiveResponseData/TriageSearches/ssh_authorized_keys.txt
find / -name authorized_keys >> $computername/LiveResponseData/TriageSearches/ssh_authorized_keys.txt
echo "find / -name authorized_keys"

# persistence check: find any scheduled tasks for root
echo "persistence check: find any scheduled tasks for root
EXAMPLE: * * * * * /tmp/.d >/dev/null 2>&1
crontab -l
**********" >> $computername/LiveResponseData/TriageSearches/sched_tasks_root.txt
crontab -l >> $computername/LiveResponseData/TriageSearches/sched_tasks_root.txt
echo "crontab -l"

# persistence check: find users with UID 0/GID 0
echo "persistence check: find users with UID 0/GID 0
grep ":0:" /etc/passwd
**********" >> $computername/LiveResponseData/TriageSearches/usrs_with_uid0.txt
grep ":0:" /etc/passwd >> $computername/LiveResponseData/TriageSearches/usrs_with_uid0.txt
echo "grep ":0:" /etc/passwd"

# persistence check: check sudoers file
echo "persistence check: check sudoers file
cat /etc/group
**********" >> $computername/LiveResponseData/TriageSearches/cat_etc_group.txt
cat /etc/group >> $computername/LiveResponseData/TriageSearches/cat_etc_group.txt
echo "cat /etc/group"

echo "persistence check: check sudoers file
cat /etc/sudoers
**********" >> $computername/LiveResponseData/TriageSearches/cat_etc_sudoers.txt
cat /etc/sudoers >> $computername/LiveResponseData/TriageSearches/cat_etc_sudoers.txt
echo "cat /etc/sudoers"

# >>>>>>>>>> PROCESSING DETAILS AND HASHES <<<<<<<<<<
echo "Computing hashes of files"
echo OS Type: nix >> $computername/Processing_Details_and_Hashes.txt
echo Computername: $cname >> $computername/Processing_Details_and_Hashes.txt
echo Time stamp: $ts >> $computername/Processing_Details_and_Hashes.txt
echo >> $computername/Processing_Details_and_Hashes.txt
echo ==========MD5 HASHES========== >> $computername/Processing_Details_and_Hashes.txt
find $computername -type f \( ! -name Processing_Details_and_Hashes.txt \) -exec md5sum {} \; >> $computername/Processing_Details_and_Hashes.txt
echo >> $computername/Processing_Details_and_Hashes.txt
echo ==========SHA256 HASHES========== >> $computername/Processing_Details_and_Hashes.txt
find $computername -type f \( ! -name Processing_Details_and_Hashes.txt \) -exec shasum -a 256 {} \; >> $computername/Processing_Details_and_Hashes.txt


echo "archiving results"
tar -czf "llr_"$computername.tgz $computername
echo "archiving completed"


exit
