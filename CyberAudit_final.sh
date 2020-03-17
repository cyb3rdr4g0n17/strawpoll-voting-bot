#!/bin/sh
#Cyber Audit Script for Army Intranet Clients
#Audit Version:1.0.0
#Author:Udit Mahajan

rm -rf audit.txt Malicious_IP USB_Usage Service_Status
echo DTE/BR:________________________>> audit.txt

echo User Name:_____________________>> audit.txt

echo Role of PC:____________________>> audit.txt

Bios=$(cat /sys/class/dmi/id/bios_version)
echo "Bios Version: $Bios" >>audit.txt

Bios_Date=$(cat /sys/class/dmi/id/bios_date)
echo "Bios Date: $Bios_Date" >>audit.txt

Make_Model=$(cat /sys/class/dmi/id/product_name)
echo "Make and Model: $Make_Model" >> audit.txt

Comp_Ser=$(cat /sys/class/dmi/id/product_serial)
echo "Computer Serial No: $Comp_Ser">> audit.txt

Hostname=$(hostname)
echo "Hostname: $Hostname" >> audit.txt

Linux=$(lsb_release -r | cut -f2)
echo "Linux Version: $Linux" >> audit.txt

Kernel=$(uname -a  | cut -d' ' -f6,7)
echo "Kernel Version: $Kernel" >> audit.txt

Glibc=$(ldd --version | grep ldd | cut -d' ' -f2,3,4)
echo "GLIBC Version: $Glibc" >> audit.txt

Install=$(stat /var/log/installer/ | head -6 | cut -d' ' -f2 | tail -1)
echo "Installed Date: $Install" >>audit.txt

touch ip1 ip2
ifconfig | grep Bcast >> ip1
cat ip1 | awk '{print $2}' >> ip2
sed -i 's/addr://' ip2
IP=$(cat ip2)
echo "IP Address: $IP" >>audit.txt
rm -rf ip1 ip2

MAC=$(ifconfig -a | awk '/^[a-z]/ { iface=$1; mac=$NF; next } /inet addr:/ { print iface, mac }' | head -1 | cut -d' ' -f2)
echo "MAC Address: $MAC" >>audit.txt

LAN=$(ifconfig -a | grep eth | wc -l)
echo "Number of LAN Cards: $LAN" >>audit.txt

Firefox=$(firefox -v | cut -d' ' -f3)
echo "Firefox Version: $Firefox" >> audit.txt


Chromium=$(chromium --version | cut -d' ' -f2)
echo "Chromium Version: $Chromium" >>audit.txt

Users=$(cat /etc/passwd | grep '/bash' | cut -d: -f1 | tail -n +2 | wc -l)
echo "Number of users: $Users" >> audit.txt

#ClientStatus=$(cat /var/log/client/process.log | grep -e "Approved" | head -1)
#if [ -z "$ClientStatus" ]
#then
#        echo "Computer Registered: No" >>audit.txt
#else
#        echo "Computer Registered: Yes" >>audit.txt
#fi

Serverip=$(cat /usr/client/serverip)
echo "Server IP: $Serverip" >>audit.txt

Update=$(stat /var/log/unattended-upgrades/unattended-upgrades.log | grep Modify | cut -d' ' -f2)
if [ -z "$Update" ]
then
        echo "PC Updated: No" >>audit.txt
else
        echo "PC Updated: $Update" >>audit.txt
fi

netstat -tulpn >> Malicious_IP
echo "Malicious IP: Check manually in file:\"Malicious_IP\"" >> audit.txt

Pass=$(cat /boot/grub/grub.cfg | grep password_pbkdf2)
if [ -z "$Pass" ]
then
        echo "Grub Password Protected: No" >>audit.txt
else
        echo "Grub Password Protected: Yes" >>audit.txt
fi

Time=$(cat /boot/grub/grub.cfg | grep timeout=10)
if [ -z "$Time" ]
then
        echo "Is Grub Loader Time Correct: No">> audit.txt
else
        echo "Is Grub Loader Time Correct: Yes">> audit.txt
fi

Secure=$(stat /boot/grub/grub.cfg | head -4 | cut -d' ' -f2 | tail -1 | cut -c2-5)
if [ $Secure = 0600 ]
then
        echo "Grub Loader File Secured: Yes" >> audit.txt
else
        echo "Grub Loader File Secured: No" >> audit.txt
fi

Root=$(grep "root\:\!\:" /etc/shadow)
if [ -z "$Root" ]
then
        echo "Root User Disabled and Locked: No" >> audit.txt
else
        echo "Root User Disabled and Locked: Yes" >> audit.txt
fi

Core=$(cat /proc/sys/fs/suid_dumpable)
if [ $Core -eq 0 ]
then
        echo "Access to Core Dumps Restricted: Yes">> audit.txt
else
        echo "Access to Core Dumps Restricted: No">> audit.txt
fi

Buffer=$(dmesg | grep '[NX|Dx]*protection' | cut -d' ' -f10)
if [ $Buffer = active ]
then
        echo "Buffer Overflow Protection Enabled: Yes" >> audit.txt
else
        echo "Buffer Overflow Protection Enabled: No" >> audit.txt
fi

Virtual=$(cat /proc/sys/kernel/randomize_va_space)
if [ $Virtual -eq 2 ]
then
        echo "Virtual Memory Region Placement Randomization Enabled: Yes" >> audit.txt
else
        echo "Virtual Memory Region Placement Randomization Enabled: No" >> audit.txt
fi

Firewall=$(ufw status | cut -d' ' -f2 | head -1)
echo "Firewall Status: $Firewall" >>audit.txt

iptables=$(iptables -V | cut -d' ' -f2)
echo "Firewall Version: $iptables" >> audit.txt


Antivirus=$(/etc/init.d/clamav-freshclam status | grep Active | cut -d' ' -f5)
echo "Antivirus Status: $Antivirus" >> audit.txt

Update=$(stat /var/log/clamav/freshclam.log | grep Modify | cut -d' ' -f2)
echo "Antivirus Last Updated: $Update">>audit.txt

cat /var/log/syslog | grep USB >> USB_Usage
echo "Check USB Usage Manually in file:\"USB_Usage\".">> audit.txt
chmod 755 USB_Usage

Blacklist=$(grep -e "^install btusb \/bin\/true" -e "^install joydev \/bin\/true" -e "^install uvcvideo \/bin\/true" -e "^install videodev \/bin\/true" -e "^install msdos \/bin\/true" -e "^install Bluetooth \/bin\/true" /etc/modprobe.d/wifi.conf)
Blacklist_count=$(echo "$Blacklist" | wc -l)
if [ $Blacklist_count -eq 6 ] || [ $Blacklist_count -eq 5 ]
then
        echo "Access to unwanted files restricted: Yes" >>audit.txt
else
        echo "Access to unwanted files restricted: No" >>audit.txt
fi

PASS_MAX_DAYS=$(grep -e "^PASS_MAX_DAYS" /etc/login.defs | cut -c17-18)
PASS_MIN_DAYS=$(grep -e "^PASS_MIN_DAYS" /etc/login.defs | cut -c17)
PASS_WARN_AGE=$(grep -e "^PASS_WARN_AGE" /etc/login.defs | cut -c17)


if [ $PASS_MAX_DAYS -eq 15 ] && [ $PASS_MIN_DAYS -eq 1 ] && [ $PASS_WARN_AGE -eq 7 ]
then
        echo "Password policy implemented: Yes">>audit.txt
else
        echo "Password policy implemented: No">>audit.txt
fi

if [ -e /etc/security/opasswd ]
then
        echo "Password reuse restricted: Yes">>audit.txt
else
        echo "Password reuse restricted: No">>audit.txt
fi

service --status-all >> Service_Status
echo "Services Status: Check status manually in file:\"Services_Status\"." >> audit.txt
chmod 755 Service_Status

MTab=$(grep -e "shm.tmpfs." /etc/mtab -c)

if [ -z "$MTab" ] || [ $MTab -eq 0 ]
then
        echo "Status of secured shared memory: No" >>audit.txt
else
        echo "Status of secured shared memory: Yes" >>audit.txt
fi

ssh=$(ufw status | grep 22 | cut -d' ' -f26 | head -1)
if [ $ssh = DENY ]
then
        echo  "SSH Root Login Disabled: Yes" >> audit.txt
else
        echo  "SSH Root Login Disabled: No" >> audit.txt
fi

iPv6=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
if [ $iPv6 -eq 1 ]
then
        echo "IPv6 Disabled: Yes">> audit.txt
else
        echo "IPv6 Disabled: No">> audit.txt
fi

Spoof=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)
if [ $Spoof -eq 1 ]
then
        echo "IP Spoofing Prevented: Yes">> audit.txt
else
        echo "IP Spoofing Prevented: No">> audit.txt
fi

Protect=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)
if [ $Protect -eq 1 ]
then
        echo "IP Spoofing Protection Enabled: Yes">> audit.txt
else
        echo "IP Spoofing Protection Enabled: No">> audit.txt
fi

Log=$(cat /proc/sys/net/ipv4/conf/all/log_martians)
if [ $Log -eq 0 ]
then
        echo "Spoof Packets Logged: Yes">> audit.txt
else
        echo "Spoof Packets Logged: No">> audit.txt
fi

Route=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route)
if [ $Route -eq 0 ]
then
        echo "IP Source Routing Disabled: Yes">> audit.txt
else
        echo "IP Source Routing Disabled: No">> audit.txt
fi


Suspicious=$(cat /proc/sys/net/ipv4/conf/default/log_martians)
if [ $Suspicious -eq 0 ]
then
        echo "Suspicious Packets Logging Enabled: Yes">> audit.txt
else
        echo "Suspicious Packets Logging Enabled: Yes">> audit.txt
fi

Forward=$(cat /proc/sys/net/ipv4/ip_forward)
if [ $Forward -eq 0 ]
then
        echo "IP Forwarding Disabled: Yes">> audit.txt
else
        echo "IP Forwarding Disabled: No">> audit.txt
fi

Pack_All=$(cat /proc/sys/net/ipv4/conf/all/send_redirects)
Pack_Def=$(cat /proc/sys/net/ipv4/conf/default/send_redirects)
if [ $Pack_All -eq 0 ] && [ $Pack_Def -eq 0 ]
then
        echo "Send Packets Redirect Disabled: Yes" >> audit.txt
else
        echo "Send Packets Redirect Disabled: No" >> audit.txt
fi

Source_All=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route)
Source_Def=$(cat /proc/sys/net/ipv4/conf/default/accept_source_route)
if [ $Source_All -eq 0 ] && [ $Source_Def -eq 0 ]
then
        echo "Source Rooted Packet Acceptance Disabled: Yes" >> audit.txt
else
        echo "Source Rooted Packet Acceptance Disabled: No" >> audit.txt
fi

Redirect_All=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects)
Redirect_Def=$(cat /proc/sys/net/ipv4/conf/default/accept_redirects)
if [ $Redirect_All -eq 0 ] && [ $Redirect_Def -eq 0 ]
then
        echo "ICMP Redirect Acceptance Disabled: Yes" >> audit.txt
else
        echo "ICMP Redirect Acceptance Disabled: No" >> audit.txt
fi

Sec_All=$(cat /proc/sys/net/ipv4/conf/all/secure_redirects)
Sec_Def=$(cat /proc/sys/net/ipv4/conf/default/secure_redirects)
if [ $Sec_All -eq 0 ] && [ $Sec_Def -eq 0 ]
then
        echo "Secure ICMP Redirect Acceptance Disabled: Yes" >> audit.txt
else
        echo "Secure ICMP Redirect Acceptance Disabled: No" >> audit.txt
fi

Cookies=$(cat /proc/sys/net/ipv4/tcp_syncookies)
if [ $Cookies -eq 1 ]
then
        echo "TCP SYN Cookies Enabled: Yes" >> audit.txt
else
        echo "TCP SYN Cookies Enabled: No" >> audit.txt
fi

Broadcast=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
Response=$(cat /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses)
if [ $Broadcast -eq 1 ] && [ $Response -eq 1 ]
then
        echo "ICMP Echo Ignore Broadcasts/Bogus Error Responses Enabled: Yes" >> audit.txt
else
        echo "ICMP Echo Ignore Broadcasts/Bogus Error Responses Enabled: No" >> audit.txt
fi

Wireless=$(cat /etc/modprobe.d/wifi.conf | grep wireless)
if [ -z "$Wireless" ]
then
        echo "Wireless Modules Disabled: No" >> audit.txt
else
        echo "Wireless Modules Disabled: Yes" >> audit.txt
fi

echo "Java Disabled: Check manually in browser" >> audit.txt

uidcheck=$(cat /etc/passwd | cut -d":" -f3 | grep "^0" -c)
if [ $uidcheck -eq 1 ]
then
        echo "Root Accts permission sys defined: Yes">>audit.txt
else
        echo "Root Accts permission sys defined: No">>audit.txt
fi

suaccess=$(grep -e "^auth       required" -c /etc/pam.d/su)
if [ $suaccess -eq 1 ] || [ $suaccess -eq 2 ]
then
        echo "Access to the su restricted: Yes" >>audit.txt
else
        echo "Access to the su restricted: No" >>audit.txt
fi

date=$(date)
echo "System Date: $date" >> audit.txt

echo Audited by:__________________  >> audit.txt

echo Date of Audit:_________________ >> audit.txt

