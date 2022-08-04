#!/bin/bash
#
#INITIAL SETUP
ScriptStart=$(date +%s)
lrcbuildname="LLR_v4.5"
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

# >>>>>>>>>> THINGS TO RUN FIRST <<<<<<<<<<
# get root bash history
echo "get root bash_history
cat /root/.bash_history
**********" >> $computername/LiveResponseData/SystemInfo/root-bash_History.txt
cat /root/.bash_history >> $computername/LiveResponseData/SystemInfo/root-bash_History.txt
echo "cat /root/.bash_history"

echo "cat /user_root/.bash_history
cat /user_root/.bash_history
**********" >> $computername/LiveResponseData/SystemInfo/userroot-bash_History.txt
cat /user_root/.bash_history >> $computername/LiveResponseData/SystemInfo/userroot-bash_History.txt
echo "cat /user_root/.bash_history"

#dump process environments
mkdir -p $computername/LiveResponseData/SystemInfo/environ
echo "dumping process environments"
for i in `find /proc -name 'environ'`; do
  new=`echo $i |sed 's|^/proc/||' |sed 's|/|_|g'`
  cp $i $computername/LiveResponseData/SystemInfo/environ/$new
  strings $i > $computername/LiveResponseData/SystemInfo/environ/${new}.strings
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
echo "fdisk -l
***********" >> $computername/LiveResponseData/SystemInfo/Partition_tables.txt
fdisk -l >> $computername/LiveResponseData/SystemInfo/Partition_tables.txt
echo "fdisk -l"
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
**********" >> $computername/LiveResponseData/SystemInfo/loadavg.txt
cat /proc/loadavg >> $computername/LiveResponseData/SystemInfo/loadavg.txt
echo "cat /proc/loadavg"
#
echo "dmesg
command on most Unix-like operating systems that prints the message buffer of the kernel. The output of this command typically contains the messages produced by the device drivers.
dmesg
***********" >> $computername/LiveResponseData/SystemInfo/dmesg.txt
dmesg >> $computername/LiveResponseData/SystemInfo/dmesg.txt
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
***********" >> $computername/LiveResponseData/SystemInfo/vmstat.txt
cat /proc/vmstat >> $computername/LiveResponseData/SystemInfo/vmstat.txt
echo "vmstat"
#
echo "mount points
cat /proc/mounts
**********" >> $computername/LiveResponseData/SystemInfo/mounts.txt
cat /proc/mounts >> $computername/LiveResponseData/SystemInfo/mounts.txt
echo "cat /proc/mounts"
#
echo "Partitions
cat /proc/partitions
**********" >> $computername/LiveResponseData/SystemInfo/partitions.txt
cat /proc/partitions >> $computername/LiveResponseData/SystemInfo/partitions.txt
echo "cat /proc/partitions"
#
echo "swap partitions
cat /proc/swaps
**********" >> $computername/LiveResponseData/SystemInfo/swap_partitions.txt
cat /proc/swaps >> $computername/LiveResponseData/SystemInfo/swap_partitions.txt
echo "cat /proc/swaps"
#
echo "Disk information
df -k
**********" >> $computername/LiveResponseData/SystemInfo/disk_info.txt
df -k >> $computername/LiveResponseData/SystemInfo/disk_info.txt
echo "df -k"
#
echo "running processes
ps -T
**********" >> $computername/LiveResponseData/SystemInfo/running_proceeses.txt
ps -T >> $computername/LiveResponseData/SystemInfo/running_proceeses.txt
echo "ps -T"
#
echo "lsof
***********" >> $computername/LiveResponseData/SystemInfo/lsof.txt
lsof >> $computername/LiveResponseData/SystemInfo/lsof.txt
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
**********" >> $computername/LiveResponseData/SystemInfo/proc_modules.txt
cat /proc/modules >> $computername/LiveResponseData/SystemInfo/proc_modules.txt
echo "cat proc/modules"
#
# sysctl -A >> $computername/LiveResponseData/SystemInfo/sysctl-A.txt
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
cat /proc/devices >> $computername/LiveResponseData/SystemInfo/proc_devices
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
An './llr_v4.5.sh: line XXX: selinux: command not found' error
is not cause for concern, selinux may not be installed.
**********" >> $computername/LiveResponseData/SystemInfo/selinux_status.txt
selinux >> $computername/LiveResponseData/SystemInfo/selinux_status.txt
echo "sestatus"

echo "SSH configuration details
cat /etc/ssh/sshd_config
**********" >> $computername/LiveResponseData/SystemInfo/sshd_config.txt
cat /etc/ssh/sshd_config >> $computername/LiveResponseData/SystemInfo/sshd_config.txt
echo "cat /etc/ssh/sshd_config"

echo "Global configuration check: DNS name servers. Check for overrides
cat /etc/resolv.conf
**********" >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
cat /etc/resolv.conf >> $computername/LiveResponseData/SystemInfo/dns_resolv.conf.txt
echo "cat /etc/resolv.conf"

echo "Global configuration check: Check for suspicious host file alterations.
Example: User directed to 1.1.1.1 when trying to go to google.com
1.1.1.1    www.google.com
cat /etc/hosts
**********" >> $computername/LiveResponseData/SystemInfo/etc_hosts.txt
cat /etc/hosts >> $computername/LiveResponseData/SystemInfo/etc_hosts.txt
echo "cat /etc/hosts"


# >>>>>>>>>> GENERAL NETWORK INFORMATION <<<<<<<<<<

# warning: certain commands such as netstat, arp, and ifconfig
# may fail on Ubuntu 18.04.6, 20.04.2, and 20.04.3

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
arp -an
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
**********" >> $computername/LiveResponseData/NetworkInfo/arpcache.txt
cat /proc/net/arp >> $computername/LiveResponseData/NetworkInfo/arpcache.txt
echo "cat /proc/net/arp"
#
echo "netstat -antp
**********" >> $computername/LiveResponseData/NetworkInfo/netstat-programs.txt
netstat -antp >> $computername/LiveResponseData/NetworkInfo/netstat-programs.txt
echo "netstat -antp"
#
echo "netstat -anp
**********" >> $computername/LiveResponseData/NetworkInfo/netstat-ports.txt
netstat -anp >> $computername/LiveResponseData/NetworkInfo/netstat-ports.txt
echo "netstat -anp"
#
echo "echo ifconfig -s
**********" >> $computername/LiveResponseData/NetworkInfo/interface_errors.txt
echo ifconfig -s >> $computername/LiveResponseData/NetworkInfo/interface_errors.txt
echo "ifconfig -s"
#
echo "lsof -P -n -i -V
**********" >> $computername/LiveResponseData/NetworkInfo/process_connections.txt
lsof -P -n -i -V >> $computername/LiveResponseData/NetworkInfo/process_connections.txt
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
echo "find / -type d -name \".*\""

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
ls -lapH /bin
**********" >> $computername/LiveResponseData/TriageSearches/bin_dir_list.txt
ls -lapH /bin >> $computername/LiveResponseData/TriageSearches/bin_dir_list.txt
echo "ls -lap /bin"

# deleted binaries still running
echo "
EXAMPLE: lrwxrwxrwx 1 root root 0 Nov 13 07:39 /proc/10580/exe -> /usr/bin/perl (deleted)
Why is a binary still running if deleted?
ls -alR /proc/*/exe | grep deleted
An 'ls: cannot read symbolic link /proc/*/exe: No such file or directory error' error
is not cause for concern, the process might not have an exe file. 
**********" >> $computername/LiveResponseData/TriageSearches/deleted_binaries_still_running.txt
ls -alR /proc/*/exe | grep deleted >> $computername/LiveResponseData/TriageSearches/deleted_binaries_still_running.txt
echo "ls -alR /proc/*/exe | grep deleted"

# binaries running from temp directories
echo "binaries running from temp directories, always suspicious
EXAMPLE: lrwxrwxrwx 1 root root 0 Nov 14 02:07 /proc/10580/cwd -> /tmp
ls -alR /proc/*/exe | grep tmp
An 'ls: cannot read symbolic link /proc/*/exe: No such file or directory error' error
is not cause for concern, the process might not have an exe file. 
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
lsattr -R / | grep \"----i\"
**********" >> $computername/LiveResponseData/TriageSearches/immutable_files.txt
lsattr -R / | grep \"----i\" >> $computername/LiveResponseData/TriageSearches/immutable_files.txt
echo "lsattr / -R  | grep \"----i\""

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
echo "persistence check: list groups
cat /etc/group
**********" >> $computername/LiveResponseData/TriageSearches/cat_etc_group.txt
cat /etc/group >> $computername/LiveResponseData/TriageSearches/cat_etc_group.txt
echo "cat /etc/group"

echo "persistence check: check sudoers file
cat /etc/sudoers
**********" >> $computername/LiveResponseData/TriageSearches/cat_etc_sudoers.txt
cat /etc/sudoers >> $computername/LiveResponseData/TriageSearches/cat_etc_sudoers.txt
echo "cat /etc/sudoers"

# fileless execution: memfd_create() Fileless Attack
echo "fileless execution: memfd_create() Fileless Attack
memfd_create() creates an anonymous file and returns a file descriptor that refers to it.  The file behaves like a regular file,
and so can be modified, truncated, memory-mapped, and so on.  However, unlike a regular file, it lives in RAM and has a volatile
backing storage. Consider any findings suspicious and follow up by checking the PID (i.e. 14667) in the proc dump results.
EXAMPLE: lrwxrwxrwx 1 root root 0 Jul  8 23:37 /proc/14667/exe -> /memfd: (deleted)
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
ls -alR /proc/*/exe 2> /dev/null | grep memfd:.*\(deleted\)
**********" >> $computername/LiveResponseData/TriageSearches/memfd_create_attack.txt
ls -alR /proc/*/exe 2> /dev/null | grep memfd:.*\(deleted\) >> $computername/LiveResponseData/TriageSearches/memfd_create_attack.txt
echo "ls -alR /proc/*/exe 2> /dev/null | grep memfd:.*\(deleted\)"

# search process environments for notables
echo "Examine key process environment details
The triage search extracts the CWD and EXE value for each process
CWD values under root tend to be suspicious
EXE values that are deleted or running from non-standard directories are suspicious
EXAMPLE: cwd -> /root
EXAMPLE: exe -> 'memfd: (deleted)' << usually this point to an actual directory, this is a nonexistent location
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
**********" >> $computername/LiveResponseData/TriageSearches/proc_cwd_exe_details.txt
#list only directories, grep out only those that are numbers and save to file
ls -d /proc/* | grep -E '[0-9]{1,5}' > $computername/LiveResponseData/Logs/environ/proc_pid_list.txt
#Reads the above proc list file line by line and inserts each line element as the searchs variable, extracts the key elements and saves results
proc_pid_list=$computername/LiveResponseData/Logs/environ/proc_pid_list.txt
proc_exp=$computername/LiveResponseData/TriageSearches/proc_cwd_exe_details.txt
while IFS= read line
do
  echo "$line" >> $proc_exp
  ls -la "$line" | grep -E '(cwd|exe)' >> $proc_exp
  echo "" >> $proc_exp
done < "$proc_pid_list"
echo "Gathering process cwd and exe details"

#COMM and CMDLINE agreement check
echo "COMM and CMDLINE agreement check
Each process environment has a COMM and CMDLINE file. Expect an actual binary name. In most instances, the binary reference is each should match. A mismatch is suspicious.
EXAMPLE (match): COMM: gpg-agent
EXAMPLE (match): CMDLINE: /usr/bin/gpg-agent--supervised
EXAMPLE (mismatch): COMM: 3
EXAMPLE (mismatch): CMDLINE: [kworker/0:pop]
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
**********" >> $computername/LiveResponseData/TriageSearches/proc_comm_cmdline_agreement.txt
proc_pid_list=$computername/LiveResponseData/Logs/environ/proc_pid_list.txt
proc_exp=$computername/LiveResponseData/TriageSearches/proc_comm_cmdline_agreement.txt
while IFS= read line
do
  echo "$line" >> $proc_exp
  cat "$line/comm" >> $proc_exp
  strings "$line/cmdline" >> $proc_exp
  echo "" >> $proc_exp
  echo "" >> $proc_exp
done < "$proc_pid_list"
echo "Gathering process details for COMM|CMDLINE agreement"

#Process maps with memfd reference
echo "Check for any process map with a reference to memfd
Search greps only for entries with 'memfd'
The file /proc/<PID>/maps will contain process mappings for a binary. This will show the binary name, plus other library files it is using when it runs. Normally the first part of this file contains a reference to the actual binary that is running (e.g. /usr/bin/vi). References to /memfd: (deleted) may be suspicious.
EXAMPLE: /memfd: (deleted)
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
**********" >> $computername/LiveResponseData/TriageSearches/proc_memfd_map.txt
proc_pid_list=$computername/LiveResponseData/Logs/environ/proc_pid_list.txt
proc_exp=$computername/LiveResponseData/TriageSearches/proc_memfd_map.txt
while IFS= read line
do
  echo "$line" >> $proc_exp
  cat "$line/maps" | grep -E 'memfd.*deleted' >> $proc_exp
  echo "" >> $proc_exp
  echo "" >> $proc_exp
done < "$proc_pid_list"
echo "Gathering process map details with memfd references"

#Process environ with ssh reference
echo "Check process environ files for ssh details
Commands started over SSH will often show the client IP address that did it in this area.
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-memfd_create-fileless-malware-with-command-line-forensics/
**********" >> $computername/LiveResponseData/TriageSearches/proc_environ_ssh.txt
proc_pid_list=$computername/LiveResponseData/Logs/environ/proc_pid_list.txt
proc_exp=$computername/LiveResponseData/TriageSearches/proc_environ_ssh.txt
while IFS= read line
do
  echo "$line" >> $proc_exp
  strings "$line/environ" | grep -E -i 'ssh' >> $proc_exp
  echo "" >> $proc_exp
  echo "" >> $proc_exp
done < "$proc_pid_list"
echo "Gathering process environ ssh details"

# Kernel Process Masquerading: search 1
echo "Kernel Process Masquerading: search 1
Checks all the system PIDs and see which ones are named with brackets and have maps files. Normally you should see nothing here. Anything that shows data should be investigated further.
EXAMPLE:
PID: 1234   << Normal, no output below
PID: 1235   << Normal, no output below
PID: 1236   << Normal, no output below
PID: 1237   << NOT Normal per the output below
..... \tmp\[kworkerd]   << NOT Normal, Maps output for PID 1237
..... \tmp\[kworkerd]   << NOT Normal, Maps output for PID 1237
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/#more-2777
ps auxww | grep \\[ | awk '{print \$2}' | xargs -I % sh -c 'echo PID: %; cat /proc/%/maps'
**********" >> $computername/LiveResponseData/TriageSearches/kernel_proc_masq_1.txt
ps auxww | grep \\[ | awk '{print $2}' | xargs -I % sh -c 'echo PID: %; cat /proc/%/maps' >> $computername/LiveResponseData/TriageSearches/kernel_proc_masq_1.txt
echo "ps auxww | grep \\[ | awk '{print \$2}' | xargs -I % sh -c 'echo PID: %; cat /proc/%/maps'"

# Kernel Process Masquerading: search 2
echo "Kernel Process Masquerading: search 2
Detects a normal process hiding as a kernel thread. Any results that show a hash value are suspicious.
EXAMPLE:
PID: 1234   << Normal, no hash
PID: 1235   << Normal, no hash
PID: 1236   << Normal, no hash
PID: 1237   <sha256hash>    <<  process hiding as a kernel thread
More Info: hxxps://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/#more-2777
ps auxww | grep \\[ | awk '{print \$2}' | xargs -I % sh -c 'echo PID: %; sha256sum /proc/%/exe''
**********" >> $computername/LiveResponseData/TriageSearches/kernel_proc_masq_2.txt
ps auxww | grep \\[ | awk '{print $2}' | xargs -I % sh -c 'echo PID: %; sha256sum /proc/%/exe' >> $computername/LiveResponseData/TriageSearches/kernel_proc_masq_2.txt
echo "ps auxww | grep \\[ | awk '{print \$2}' | xargs -I % sh -c 'echo PID: %; sha256sum /proc/%/exe''"

# SHA256 hash for each running process
echo "SHA256 hash for each running process
Checks all the system PIDs and calculates the SHA256 hash for each process executable.
EXAMPLE:
<sha256hash>  /proc/100/exe
<sha256hash>  /proc/101/exe
<sha256hash>  /proc/102/exe
sha256sum /proc/*/exe'
**********" >> $computername/LiveResponseData/TriageSearches/running_procs_sha256.txt
sha256sum /proc/*/exe >> $computername/LiveResponseData/TriageSearches/running_procs_sha256.txt
echo "sha256sum /proc/*/exe"

# Dumping all EXEs from memory by PID [Optional]
echo "Dumping all EXEs from memory by PID"
mkdir $computername/LiveResponseData/TriageSearches/binaries_from_memory
proc_pid_list=$computername/LiveResponseData/Logs/environ/proc_pid_list.txt
pids_only=$computername/LiveResponseData/Logs/environ/pids_only.txt
dump_res=$computername/LiveResponseData/TriageSearches/binaries_from_memory
grep -E -o '[0-9]{1,5}' $proc_pid_list >> $pids_only
while IFS= read line
do
  cp "/proc/$line/exe" $dump_res/$line.recovered
done < "$pids_only"

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
find $computername -type f \( ! -name Processing_Details_and_Hashes.txt \) -exec sha256sum {} \; >> $computername/Processing_Details_and_Hashes.txt


echo "archiving results"
tar -czf "llr_"$computername.tgz $computername
echo "archiving completed"


exit
