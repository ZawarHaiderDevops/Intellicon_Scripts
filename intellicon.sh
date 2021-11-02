#!/bin/bash
set -e
set -o pipefail

function check_pre() {
#Check Connection Link Variables
LINK1="www.google.com"
OUT="/tmp/test.txt"

BACKTITLE="INTELLICON Starter Script by Contegris"
DIR="/var/log/intellicon"
LOG="/var/log/intellicon/install_intellicon.log"

#Check Memory Var. Set INTELLICON_MIN_MEM in byte.
INTELLICON_MIN_MEM=1500                                                         #Memory Size in Mbytes
HOST_MEM=$(free -m | awk 'NR==2{print $2 }')

#Check Disk Var. Set INTELLICON_MIN_DISK in Kbyte.
INTELLICON_MIN_DISK=2500                                                        # Disk Space in Mbytes ##       Requirements of INTELLICON 40-GB minimum disk space
HOST_DISK=$(df -m | awk '$NF=="/"{print $4 }')

#Check CPU Var.
CPUNUM=$( cat /proc/cpuinfo | grep processor | wc -l )

# Store menu options selected by the user
INPUT=/tmp/menu.sh.$$
# Storage file for displaying command output
OUTPUT=/tmp/output.sh.$$
# trap and delete temp files
trap "rm $OUTPUT; rm $INPUT; exit" SIGHUP SIGINT SIGTERM

#Init Installer LOG file
now=$(date +"%d-%m-%Y %T")
if [ -d $DIR ]; then
echo "INTELLICON Directory under /var/log/ is alreday exist" |& tee -a $LOG
else
        mkdir $DIR
fi

touch $LOG
chmod 640 $LOG
echo "########################################"  |& tee -a $LOG
echo "#### INTELLICON INSTALLER LOG FILE  ####"  |& tee -a $LOG 
echo "########################################"  |& tee -a $LOG
echo "##CHECK SYSTEM AND INSTALL DEPENDENCIES#"  |& tee -a $LOG
echo "#INTELLICON Installer Script started on $now#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

#Check dependencies.. Check For wget.
sleep 1
echo "Checking for wget..."
if ! type "wget" > /dev/null 2>&1; then
echo "Wget is not installed, installing...!!!" |& tee -a $LOG
sleep 2
yum --assumeyes install wget |& tee -a $LOG
fi
echo "Wget is installed...!!!" |& tee -a $LOG

if ! type "deltarpm" > /dev/null 2>&1; then
echo "Deltarpm is not installed, installing...!!!" |& tee -a $LOG
sleep 2
yum --assumeyes install deltarpm |& tee -a $LOG
fi
echo "Deltarpm has been installed successfully" |& tee -a $LOG

clear  |& tee -a $LOG
touch /tmp/npm |& tee -a $LOG
touch /tmp/npm1 |& tee -a $LOG
touch /tmp/npm2 |& tee -a $LOG
touch /tmp/npm3 |& tee -a $LOG
echo "npm install" > /tmp/npm  |& tee -a $LOG
echo "npm install yarn -g" > /tmp/npm1  |& tee -a $LOG
echo "yarn install --ignore-engines" > /tmp/npm2  |& tee -a $LOG
echo "node install.js" > /tmp/npm3  |& tee -a $LOG
#Wait for next part of the script.
#dialog --infobox "Checking for dialog..." 20 70 ; sleep 1
if ! type "dialog" > /dev/null 2>&1; then
echo "Dialog is not installed, installing...!!!" |& tee -a $LOG
sleep 2
yum --assumeyes install dialog |& tee -a $LOG
fi
echo "Dialog is installed...!!!" |& tee -a $LOG
}
u="devops"
p="8zKg2itIx9lr0Nnl1ofNLP0P0veDEQHA"
check_pre

function system_update() {
if [ $(yum check-update | grep update | tail -n +2 | wc -l) == 0 ];then
echo "System is already updated" |& tee -a $LOG
else
        clear
        echo 'System Packages update is available'
        echo 'After System Packages update system will reboot automatically'
        echo '#####################'
        echo '###################'
        echo '#################'
        echo '###############'
        echo '#############'
        echo '###########'
        echo '#########'
        echo '#######'
        echo '#####'
        echo '###'
        echo '#'
        read -p "Please Type (yes/no) : " INPUT
                        if [ "$INPUT" == "yes" ] || [ "$INPUT" == "YES" ] || [ "$INPUT" == "Yes" ] || [ "$INPUT" == "y" ] || [ "$INPUT" == "Y" ]; then
                                yum --assumeyes update  |& tee -a $LOG
                                yum --assumeyes screen  |& tee -a $LOG
                                echo "System has been updated successfully" |& tee -a $LOG
                                reboot
                        else
                                echo 'With out System update this script will not work'
                                exit 1
                        fi
fi
}
d="git.contegris.com"

dialog --infobox "Checking for root privileges..." 20 70 ; sleep 1
if [[ $EUID -ne 0 ]]; then
echo "This script must be run as root" 1>&2
exit 1
fi
dialog --infobox "Root check successful!" 20 70 ; sleep 1

dialog --infobox "Checking CentOS distro..." 20 70 ; sleep 1
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')

if [ -f /etc/debian_version ]; then
OS=Debian
echo "Distro $OS not supported! - This script must be run in CentOS 7 distro" 1>&2
exit 1
elif [ -f /etc/redhat-release ]; then
OS=CentOS
if grep -q -i "release 6" /etc/redhat-release
then
#MAJOR=6
#dialog --infobox "CentOS 6 distro check successful!" 20 70 ; sleep 1
echo "Distro $OS not supported! - This script must be run on CentOS 7 distro" 1>&2
exit 1
elif grep -q -i "release 7" /etc/redhat-release
then
MAJOR=7
dialog --infobox "CentOS 7 distro check successful!" 20 70 ; sleep 1
else
echo "Distro $OS not supported! - This script must be run in CentOS 7 distro" 1>&2
exit 1
fi
else
OS=$(uname -s)
echo "Distro $OS not supported! - This script must be run with CentOS 6 distro" 1>&2
exit 1
fi

#Wait for next part of the script.
sleep 3
echo "Checking for ntpd..."  |& tee -a $LOG
if ! type "ntpd" > /dev/null 2>&1; then
echo "Ntpd is not installed, installing"  |& tee -a $LOG
sleep 2
yum --assumeyes install ntp |& tee -a $LOG | dialog --title "Install ntpd. Please wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100
  if [ MAJOR=7 ]; then
#       systemctl stop chronyd.service  |& tee -a $LOG 2>&1
#    systemctl disable chronyd.service  |& tee -a $LOG 2>&1
    systemctl start ntpd.service  |& tee -a $LOG 2>&1
    systemctl enable ntpd.service  |& tee -a $LOG 2>&1
        systemctl status ntpd.service  |& tee -a $LOG 2>&1
        timedatectl set-timezone Asia/Karachi  |& tee -a $LOG 2>&1
else
        echo "Exiting.....! on ntpd service."
  fi
fi
echo "Ntp is installed and functioning"  |& tee -a $LOG

function install_repo(){

REMI_DIR="/etc/yum.repos.d"
REMI="$REMI_DIR/remi.repo"
EPEL="$REMI_DIR/epel.repo"
ELREPO="$REMI_DIR/elrepo.repo"
PHP70="$REMI_DIR/remi-php70.repo"
PHP71="$REMI_DIR/remi-php71.repo"
PERCONA="$REMI_DIR/percona-release.repo"

#PERCONA_LINK="http://www.percona.com/downloads/percona-release/redhat/0.1-3/percona-release-0.1-3.noarch.rpm"
ELREPO_LINK="rpm -ivh http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm"
RPM_GPG_KEY_ELREPO_LINK="rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-elrepo.org"
EPEL_LINK="https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm"
REMI_RELEASE_7_LINK="http://rpms.remirepo.net/enterprise/remi-release-7.rpm"
XTRA_BACKUP="yum install https://repo.percona.com/yum/percona-release-latest.noarch.rpm"

if [ -f $REMI ]; then
echo "Remi is already installed" |& tee -a $LOG 
sleep 2
else
#yum -y update |& tee -a $LOG
yum -y install $REMI_RELEASE_7_LINK |& tee -a $LOG
fi

if [ -f $EPEL ]; then
echo "Epel Repo is alreday installed" |& tee -a $LOG
sleep 2
#sed -i '/baseurl/s/^#*//g' /etc/yum.repos.d/epel.repo
#sed -i '/metalink/s/^#*/#/g' /etc/yum.repos.d/epel.repo
else
yum -y  install $EPEL_LINK |& tee -a $LOG
#sed -i '/baseurl/s/^#*//g' /etc/yum.repos.d/epel.repo
#sed -i '/metalink/s/^#*/#/g' /etc/yum.repos.d/epel.repo
fi

if [ -f $ELREPO ]; then
echo "Elrepo is already installed" |& tee -a $LOG
sleep 2
else
#$ELREPO_LINK |& tee -a $LOG
#cd /tmp/ && wget http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm --no-check-certificate
#rpm -ivh /tmp/elrepo-release-7.0-2.el7.elrepo.noarch.rpm
yum update -y nss curl libcurl
$ELREPO_LINK |& tee -a $LOG
$RPM_GPG_KEY_ELREPO_LINK |& tee -a $LOG
fi

if [ -f $PHP70 ]; then
echo "$PHP70 is already installed" |& tee -a $LOG
sleep 2
else
yum -y install $REMI_RELEASE_7_LINK |& tee -a $LOG
fi

if [ -f $PHP71 ]; then
echo "$PHP71 is already installed" |& tee -a $LOG
else
yum -y install $REMI_RELEASE_7_LINK |& tee -a $LOG
fi

if [ -f $PERCONA ]; then
echo "$PERCONA is already installed" |& tee -a $LOG
else
yum install -y 'https://downloads.percona.com/downloads/percona-release/percona-release-0.1-3/redhat/percona-release-0.1-3.noarch.rpm' || cd /tmp/ && wget https://downloads.percona.com/downloads/percona-release/percona-release-0.1-3/redhat/percona-release-0.1-3.noarch.rpm --no-check-certificate
rpm --import /etc/pki/rpm-gpg/PERCONA-PACKAGING-KEY || rpm -ivh /tmp/percona-release-0.1-3.noarch.rpm
fi

if ! type "yum-utils" > /dev/null 2>&1; then
echo "yum-utils package is not installed, installing" |& tee -a $LOG
sleep 2
yum --assumeyes install yum-utils |& tee -a $LOG
fi

echo "Enble irontec repo"  |& tee -a $LOG
if [ -f /etc/yum.repos.d/sngrep.repo ]; then
echo "Repo file is already exist"  |& tee -a $LOG
else
touch /etc/yum.repos.d/sngrep.repo  |& tee -a $LOG
echo '[irontec]
name=Irontec RPMs repository
baseurl=http://packages.irontec.com/centos/$releasever/$basearch/' >> /etc/yum.repos.d/sngrep.repo  |& tee -a $LOG
echo "Repo has been created successfully"   |& tee -a $LOG
rpm --import http://packages.irontec.com/public.key   |& tee -a $LOG
fi

echo "yum-utils is installed and functioning" |& tee -a $LOG
yum-config-manager --enable remi
yum-config-manager --enable remi-php71
yum repolist
}

function install_dependecies(){

#Variables of PREREQUISITE Packages for INTELLICON , INTELLIx & INTELLIDESK
PREREQUISITE="automake bzip2 gcc gcc-c++ patch ncurses-devel sngrep net-tools yarn openssl-devel libxml2-devel unixODBC-devel libcurl-devel libogg-devel libvorbis-devel lua-devel"
PREREQUISITE="$PREREQUISITE spandsp-devel freetds-devel elinks net-snmp-devel monit net-snmp net-snmp-utils iksemel-devel corosynclib-devel newt-devel popt-devel libtool-ltdl-devel"
PREREQUISITE="$PREREQUISITE sqlite-devel libsqlite3x-devel radiusclient-ng-devel screen glances nmon portaudio-devel postgresql-devel  neon-devel libical-devel speex-devel lsyncd"
PREREQUISITE="$PREREQUISITE openldap-devel sqlite2-devel bluez-libs-devel jack-audio-connection-kit-devel mytop gsm-devel libedit-devel libuuid-devel newt-devel rsync"
PREREQUISITE="$PREREQUISITE jansson-devel libsrtp-devel pjproject-devel subversion git libxslt-devel python-devel lynx bison gmime-devel libtermcap-devel sendmail-cf openvpn"
PREREQUISITE="$PREREQUISITE bash-completion iptables-services ntp firewalld libcurl zip unzip tcpdump traceroute telnet kernel-devel make sendmail"
PREREQUISITE="$PREREQUISITE perl pciutils php-xml php php-fpm php-mysql php-pear php-mbstring psmisc tftp-server bash-completion-extras caching-nameserver libtiff-devel sox autoconf"
PREREQUISITE="$PREREQUISITE audiofile-devel uuid-devel libtool kernel-devel-$(uname -r) kernel-devel open-vm-tools fail2ban-all.noarch fail2ban php-process crontabs cronie pkgconfig"
PREREQUISITE="$PREREQUISITE cronie-anacron wget percona-xtrabackup-24 Percona-Server-server-57.x86_64 Percona-Server-client-57.x86_64 Percona-Server-devel-57.x86_64 httpd httpd-devel"
PREREQUISITE="$PREREQUISITE pcre pcre-devel mod_ssl mod_security php-gd php-pdo php-mssql php-mcrypt php-json php-imap php-soap php-mbstring php-zip php-posix vim sed"
PREREQUISITE="$PREREQUISITE gcc kernel-headers kernel-devel keepalived nginx haproxy monit nc gtk3 libXScrnSaver libXss.so.1 at-spi2-atk lsof mlocate"

if [ -f /tmp/packages ]; then
echo "All packages are already installed nothing to do...." |& tee -a $LOG
else
yum  --assumeyes install $PREREQUISITE
wget https://rpms.remirepo.net/enterprise/7/remi/x86_64/redis-6.0.15-1.el7.remi.x86_64.rpm --no-check-certificate && rpm -ivh redis-6.0.15-1.el7.remi.x86_64.rpm
touch /tmp/packages
fi 
#|& tee -a $LOG | dialog --title "Install PREREQUISITE Please wait.." --backtitle "Intellicon Starter Script By Contegris" --progressbox 40 120

echo "Checking for gtk2-devel..."
if ! type "gtk2-devel" > /dev/null 2>&1; then
echo "Gtk2-devel is not installed, installing" |& tee -a $LOG
sleep 2
yum --assumeyes install gtk2-devel || yum --assumeyes install gtk+-devel  |& tee -a $LOG
fi
echo "Gtk2-devel is installed and functioning" |& tee -a $LOG
}


function fail2ban_config() {
clear
if [ -f /etc/fail2ban/jail.local ]; then
echo "
--------------------------------------------------------------------------------
################################################################################
#            Fail2Ban is already set For Asterisk & SSH                        #
################################################################################
--------------------------------------------------------------------------------"
else
echo "
--------------------------------------------------------------------------------
################################################################################
#                     Setup Fail2Ban For Asterisk & SSH                        #
################################################################################
--------------------------------------------------------------------------------"

echo '[DEFAULT]

ignoreip        = 103.8.112.210/32
bantime         = 1800
findtime        = 600
maxretry        = 10
backend         = auto
#logpath    = /var/log/auth.log
usedns          = warn
destemail       = support@contegris.com
sendername      = Fail2Ban
banaction       = iptables-multiport
mta             = sendmail
protocol        = tcp
chain           = INPUT
action_         = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw       = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
          %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s", sendername="%(sendername)s"]
action_mwl      = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
           %(mta)s-whois-lines[name=%(__name__)s, dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s", sendername="%(sendername)s"]
action          = %(action_)s

[sshd]
enabled         = true

[asterisk]
enabled         = true
filter          = asterisk
action          = iptables-allports[name=ASTERISK, protocol=all]
sendmail-whois[name=ASTERISK, dest=support@contegris.com, sender=fail2ban@contegris.com]
logpath         = /var/log/asterisk/full
maxretry        = 10
bantime         = 86400' > /etc/fail2ban/jail.local
echo "Fail2Ban Custom settings are done for Asterisk and SSH"
systemctl enable fail2ban && systemctl start fail2ban
fi

}

function install_Dahdi() {

# Dahdi Variables
Dahdi_LINK=http://downloads.asterisk.org/pub/telephony/dahdi-linux-complete/dahdi-linux-complete-current.tar.gz
Dahdi_PKG="dahdi-linux-complete-current.tar.gz"
Dahdi_DIR=(dahdi-*)

echo "##COMPILE AND INSTALL Dahdi#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

cd /usr/src/
wget --progress=bar:force $Dahdi_LINK 2>&1 | while read -d "%" X; do sed 's:^.*[^0-9]\([0-9]*\)$:\1:' <<< "$X"; done | dialog --backtitle "${BACKTITLE}" --title "${Dahdi_PKG}"  --gauge "Downloading from ${Dahdi_LINK}..." 20 70
tar -vxzf $Dahdi_PKG && cd $Dahdi_DIR
#tar -xzf $Dahdi_PKG && rm -rf $Dahdi_PKG && cd $Dahdi_DIR

#./bootstrap.sh |& tee -a $LOG | dialog --title "Generating Dahdi configure script. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100

#cd $Dahdi_DIR
Dahdi_MAKE='make'
#$Dahdi_MAKE |& tee -a $LOG | dialog --title "Run Dahdi make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100
make |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./make and make install had problems.
echo 1>&2 $0: "$Dahdi_MAKE"  Exiting.
exit 1
else
echo "Dahdi was successfully installed"  |& tee -a $LOG
fi

Dahdi_MAKE_IN='make install'
$Dahdi_MAKE_IN |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./Dahdi samples had problems.
echo 1>&2 $0: "$Dahdi_MAKE"  Exiting.
exit 1
else
echo "Dahdi_MAKE command successfully has been run.....!"  |& tee -a $LOG
fi

#rm -rf /usr/src/$Dahdi_DIR
}

function install_lame() {
LAME_LINK="https://sourceforge.net/projects/lame/files/lame/3.99/lame-3.99.5.tar.gz"
if [ -f /usr/src/lame-3.99.5.tar.gz ]; then
echo "Lame file is already is donwloaded"
else
cd /usr/src && wget $LAME_LINK  |& tee -a $LOG
cd /usr/src && tar -zxvf lame-3.99.5.tar.gz  |& tee -a $LOG
cd /usr/src/lame-3.99.5 && ./configure && make && make install  |& tee -a $LOG
fi
}


function install_libpri() {

# Libpri Variables
Libpri_LINK="http://downloads.asterisk.org/pub/telephony/libpri/libpri-current.tar.gz"
Libpri_PKG="libpri-current.tar.gz"
Libpri_DIR=(libpri-*)

echo "##COMPILE AND INSTALL Libpri#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

#if [ -f /usr/src/libpri-current.tar.gz ]; then
#echo "Allready file is donwloaded"
#else
cd /usr/src/
#wget --progress=bar:force $Libpri_LINK 2>&1 | while read -d "%" X; do sed 's:^.*[^0-9]\([0-9]*\)$:\1:' <<< "$X"; done | dialog --backtitle "${BACKTITLE}" --title "${Libpri_PKG}"  --gauge "Downloading from ${Libpri_LINK}..." 20 70
wget $Libpri_LINK  |& tee -a $LOG
tar -vxzf $Libpri_PKG && cd $Libpri_DIR
#tar -xzf $Libpri_PKG && rm -rf $Libpri_PKG && cd $Libpri_DIR
#./bootstrap.sh |& tee -a $LOG | dialog --title "Generating Libpri configure script. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100

#cd $Libpri_DIR
Libpri_MAKE='make'
#$Libpri_MAKE |& tee -a $LOG | dialog --title "Run Libpri make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100
make |& tee -a $LOG #| dialog --title "Run Libpri make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100

if [ $? -ne 0 ]
then
# ./make and make install had problems.
echo 1>&2 $0: "$Libpri_MAKE"  Exiting.
exit 1
else
echo "Libpri was successfully installed"  |& tee -a $LOG
fi

Libpri_MAKE_IN='make install'
$Libpri_MAKE_IN |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./Libpri samples had problems.
echo 1>&2 $0: "$Libpri_MAKE"  Exiting.
exit 1
else
echo "Libpri_MAKE command successfully has been run.....!"  |& tee -a $LOG
fi
#fi
#rm -rf /usr/src/$Libpri_DIR
}

function install_libsrtp() {

# Libsrtp Variables
Libsrtp_LINK="https://github.com/cisco/libsrtp/archive/v1.5.4.tar.gz"
Libsrtp_PKG="v1.5.4.tar.gz"
Libsrtp_DIR=(libsrtp-*)

echo "##COMPILE AND INSTALL Libsrtp#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

if [ -f /usr/src/v1.5.4.tar.gz ]; then
echo "Allready file donwloaded"
else
cd /usr/src/
wget --progress=bar:force $Libsrtp_LINK 2>&1 | while read -d "%" X; do sed 's:^.*[^0-9]\([0-9]*\)$:\1:' <<< "$X"; done | dialog --backtitle "${BACKTITLE}" --title "${Libsrtp_PKG}"  --gauge "Downloading from ${Libsrtp_LINK}..." 20 70
tar -vxzf $Libsrtp_PKG && cd $Libsrtp_DIR
#tar -xzf $Libsrtp_PKG && rm -rf $Libsrtp_PKG && cd $Libsrtp_DIR

#./bootstrap.sh |& tee -a $LOG | dialog --title "Generating Libsrtp configure script. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100

echo "Please Wait. Configure Makefile Libsrtp..."  |& tee -a $LOG
Libsrtp_CONFIGURE='./configure --libdir=/usr/lib64 --enable-openssl'
$Libsrtp_CONFIGURE |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./configure had problems.
echo 1>&2 $0: "$Libsrtp_CONFIGURE"  Exiting.
exit 1
else
echo "Successfully configured Libsrtp Makefile"  |& tee -a $LOG
fi

Libsrtp_MAKE='make shared_library'
#$Libsrtp_MAKE |& tee -a $LOG | dialog --title "Run Libsrtp make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100
make |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./make and make install had problems.
echo 1>&2 $0: "$Libsrtp_MAKE"  Exiting.
exit 1
else
echo "Libsrtp was successfully installed"  |& tee -a $LOG
fi

Libsrtp_MAKE_IN='make install'
$Libsrtp_MAKE_IN |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./Libsrtp samples had problems.
echo 1>&2 $0: "$Libsrtp_MAKE"  Exiting.
exit 1
else
echo "Libsrtp_MAKE command successfully has been run.....!"  |& tee -a $LOG
fi
fi
#rm -rf /usr/src/$Libsrtp_DIR
}

function install_asterisk() {
if [ -f /tmp/asterisk_installed ]; then
echo "Asterisk already installed and Configured"
else
# ASTERISK Variables
ASTERISK_LINK="http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-14-current.tar.gz"
#ASTERISK_LINK="http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-16-current.tar.gz"
ASTERISK_PKG="asterisk-14-current.tar.gz"
ASTERISK_DIR=(asterisk-*)

echo "##COMPILE AND INSTALL ASTERISK#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

if [ -e /etc/init.d/asterisk ]; then
  /etc/init.d/asterisk stop
fi

SESTATUS=$(sestatus | awk '{print $3}' | head -n 1)
if [ $SESTATUS == disabled ]; then
echo "SELINUX is already disabled"
else
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
setenforce 0
fi
# Install Asterisk Dependencies
cd /usr/src/
if [ -f asterisk/$ASTERISK_PKG ]; then
echo "Asterisk source file version: ($ASTERISK_PKG)is already exist"
else
git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/abdullah-manzoor/asterisk_source.git asterisk
#wget $ASTERISK_LINK   |& tee -a $LOG #2>&1 | while read -d "%" X; do sed 's:^.*[^0-9]\([0-9]*\)$:\1:' <<< "$X"; done | dialog --backtitle "${BACKTITLE}" --title "${ASTERISK_PKG}"  --gauge "Downloading from ${ASTERISK_LINK}..." 20 70
fi
if [ -d /usr/src/asterisk/$ASTERISK_PKG ]; then
echo "Asterisk Directory is already exist no need to tar again"
else
tar -vxzf asterisk/$ASTERISK_PKG && cd $ASTERISK_DIR
#tar -xzf $ASTERISK_PKG && rm -rf $ASTERISK_PKG && cd $ASTERISK_DIR
fi

echo "Please Wait. Configure Makefile Asterisk..."  |& tee -a $LOG
ASTERISK_CONFIGURE='./configure libdir=/usr/lib64'
$ASTERISK_CONFIGURE |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./configure had problems.
echo 1>&2 $0: "$ASTERISK_CONFIGURE"  Exiting.
exit 1
else
echo "Successfully configured Asterisk Makefile"  |& tee -a $LOG
fi

echo "Please Wait. Make and Install Asterisk..."  |& tee -a $LOG
ASTERISK_MAKE_MENU='make menuselect.makeopts'
$ASTERISK_MAKE_MENU |& tee -a $LOG

ASTERISK_MENUSELECT='menuselect/menuselect --enable format_mp3 --enable res_config_mysql --enable app_mysql --enable cdr_mysql --enable EXTRA-SOUNDS-EN-WAV'
#ASTERISK_MENUSELECT='menuselect/menuselect --enable ODBC_STORAGE --enable codec_opus'
$ASTERISK_MENUSELECT |& tee -a $LOG

if [ -f /tmp/mp3 ]; then
echo "Already donwloaded"
else
GET_MP3_ASTERISK="contrib/scripts/get_mp3_source.sh"
$GET_MP3_ASTERISK |& tee -a $LOG
touch /tmp/mp3
fi
ASTERISK_MAKE='make -j"$CPUNUM"'
#$ASTERISK_MAKE |& tee -a $LOG | dialog --title "Run Asterisk make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100
make #-j"$CPUNUM" |& tee -a $LOG | dialog --title "Run Asterisk make. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100

ASTERISK_MAKE_IN='make install'
#$ASTERISK_MAKE_IN |& tee -a $LOG
make install
echo "Install Asterisk-Samples"  |& tee -a $LOG
ASTERISK_SAMPLES='make samples'
#$ASTERISK_SAMPLES |& tee -a $LOG
make samples

#ASTERISK_CONFIG='make config'
#$ASTERISK_CONFIG |& tee -a $LOG
if [ -f /etc/init.d/asterisk ]; then
echo "Asterisk service file exist"
else
make config
fi
ldconfig

ASTERISK_DIR_CONF="/etc/asterisk"
if [ -d $ASTERISK_DIR_CONF ]
then
cd $ASTERISK_DIR_CONF
touch extensions_additional.conf
touch extensions_custom.conf 
touch sip_registrations.conf ; chmod 777 sip_registrations.conf
touch queue_opt_out.conf ; chmod 777 queue_opt_out.conf
ls -l sip_registrations.conf queue_opt_out.conf
fi

if [ -f /var/log/asterisk/queue_log ]; then
echo "Queue Log file already exist"
else
touch /var/log/asterisk/queue_log
echo "Queue Log file has been created"
fi
#rm -rf /usr/src/$ASTERISK_DIR
touch /tmp/asterisk_installed |& tee -a $LOG
echo "Asterisk Installation has been completed successfully"  |& tee -a $LOG
fi
}

function turnserver() {
echo "we are on Turnserver"
TURNSERVER="https://github.com/downloads/libevent/libevent/libevent-2.0.21-stable.tar.gz"
TURNSERVER_1="http://turnserver.open-sys.org/downloads/v3.2.3.8/turnserver-3.2.3.8.tar.gz"
if [ -f /usr/src/libevent-2.0.21-stable.tar.gz ]; then
echo "Libevent source code is already downloaded" |& tee -a $LOG
else
cd /usr/src && wget $TURNSERVER   |& tee -a $LOG
fi

if [ -f /usr/src/turnserver-3.2.3.8.tar.gz ]; then
echo "Turnserver source code is already downloaded"  |& tee -a $LOG
else
cd /usr/src && wget $TURNSERVER_1   |& tee -a $LOG
fi

if [ -x /usr/local/bin/turnserver ]; then
echo "Libevent is already installed"  |& tee -a $LOG
else
#cd /usr/src && $TURNSERVER
cd /usr/src && tar xvfz libevent-2.0.21-stable.tar.gz  |& tee -a $LOG
cd /usr/src/libevent-2.0.21-stable && ./configure && make && make install  |& tee -a $LOG
fi

if [ -x /usr/local/bin/turnserver ]; then
echo "Turnserver is already installed"  |& tee -a $LOG
else
#cd /usr/src && $TURNSERVER
cd /usr/src && tar xvfz turnserver-3.2.3.8.tar.gz  |& tee -a $LOG
cd /usr/src/turnserver-3.2.3.8  && ./configure && make && make install  |& tee -a $LOG
fi

}

function node() {
curl -sL https://rpm.nodesource.com/setup_10.x | sudo bash - |& tee -a $LOG
yum install nodejs -y  |& tee -a $LOG
sudo npm cache clean -f |& tee -a $LOG
sudo npm install n yarn sequelize sequelize-cli mysql2 -g |& tee -a $LOG
sudo n 10.13.0 |& tee -a $LOG

if [ -f /bin/node ]; then
        echo "Setting Up the Require Node Version"
        rm -rf /bin/node
        ln -s /usr/local/bin/node /bin/
else
        echo node -v
fi
}

function install_node() {

if [ -x /usr/local/bin/node ]; then
echo "node is already installed on"
else
node
fi
}

function install_pm2() {
if [ -x /usr/local/bin/pm2 ]; then
        echo "PM2 is already installed"
else
        npm install npm@latest -g  |& tee -a $LOG
        if [ $? -ne 0 ]
                then
                echo "Command (npm install npm@latest -g) failed...!"
                exit 1
        else
                #npm install pm2 -g  |& tee -a $LOG
                npm install pm2 -g  |& tee -a $LOG
                if [ $? -ne 0 ]
                        then
                        echo "PM2 Installed Globally Failed....!"
                        exit 1
                else
                        echo "PM2 Installation Process has been completed" |& tee -a $LOG
                        echo "PM2 version is ($PM_VERSION)" |& tee -a $LOG
                fi
        fi
fi
}
# Variables for node and agi path
function git_intellcion() {
clear
echo "Going to downlload soruce code fo intellicon"
sleep 5
NODE_PATH="/etc"
AGI_PATH="/etc"
INTELLICON_PATH="/var/www/html"
INTELLICON_DIR="/var/www/html/intellicon"

INTELLICON_LINK="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/intellicon-7.1.x.git intellicon"
INTELLICON_NODE="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/node.git node"
INTELLICON_AGI="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/agispeedy-7.1.x.git agispeedy"
INTELLICON_ASTERISK="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/abdullah-manzoor/asterisk_intellicon.git intellicon_asterisk"
TAIL_GIT="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/tail.git"
IWGW_GIT="git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/iwgw.git"
STARTUP_SCRIPTS=""
if [ -d $INTELLICON_PATH/intellicon ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd $INTELLICON_PATH && $INTELLICON_LINK 
chmod -R 755 $INTELLICON_DIR  |& tee -a $LOG
chown -R apache:apache $INTELLICON_DIR  |& tee -a $LOG
chmod -R 777 $INTELLICON_DIR/sounds  |& tee -a $LOG
chmod -R 777 $INTELLICON_DIR/export  |& tee -a $LOG
cp $INTELLICON_DIR/application/scripts/intelliCallHandler.sh  /etc/asterisk/   |& tee -a $LOG
ln -s /var/spool/asterisk/monitor/ $INTELLICON_DIR/sounds/     |& tee -a $LOG
ln -s /var/spool/asterisk/voicemail/ $INTELLICON_DIR/sounds/   |& tee -a $LOG
fi

if [ -d $NODE_PATH/node ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd $NODE_PATH && $INTELLICON_NODE 
fi

if [ -d $AGI_PATH/agispeedy ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd $AGI_PATH && $INTELLICON_AGI 
chmod -R 755 /etc/agispeedy  |& tee -a $LOG
cp /etc/agispeedy/contrib/agispeedy  /etc/init.d   |& tee -a $LOG
fi

if [ -d $INTELLICON_PATH/intellicon_asterisk ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd $INTELLICON_PATH && $INTELLICON_ASTERISK 
fi

if [ -d /etc/tail ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd /etc && $TAIL_GIT
fi

if [ -d /etc/iwgw ]; then
echo "Code is already downloaded"  |& tee -a $LOG
sleep 1
else
cd /etc && $IWGW_GIT 
fi

if [ -d /etc/asterisk ]; then 
clear
yes | cp -pf /var/www/html/intellicon_asterisk/*  /etc/asterisk && ls /etc/asterisk  |& tee -a $LOG
echo "Asterisk Configuration files are copied successfully"
chmod 777 /etc/asterisk/sip_registrations.conf
ll /etc/asterisk/
sleep 1
else
echo "Asterisk samples file not exist."  |& tee -a $LOG
sleep 1
exit
fi

if [ -f /var/www/html/intellicon/application/config/config.php.org ]; then
echo "File is already exist"  |& tee -a $LOG
sleep 1
else
yes | cp /var/www/html/intellicon/application/config/config.php    /var/www/html/intellicon/application/config/config.php.org  && echo  "File has been copied"  |& tee -a $LOG
sleep 1
fi
if [ -f /var/www/html/intellicon/application/config/yovo_ajam.php.org ]; then
echo "File is already exist"
sleep 1
else
yes | cp /var/www/html/intellicon/application/config/yovo_ajam.php    /var/www/html/intellicon/application/config/yovo_ajam.php.org && echo "File has been copied"  |& tee -a $LOG
sleep 1
fi

}

function mongodb_centrifugo(){
if [[ ! -f /etc/yum.repos.d/mongodb.repo ]]; then
        touch /etc/yum.repos.d/mongodb.repo  |& tee -a $LOG
        echo '[MongoDB]
name=MongoDB Repository
baseurl=http://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/4.0/x86_64/
gpgcheck=0
enabled=1' > /etc/yum.repos.d/mongodb.repo  |& tee -a $LOG
yum makecache fast  |& tee -a $LOG
                if systemctl list-units | grep 'mondod.service'; then
                echo "MongoDB Installed" |& tee -a $LOG
                else
                yum install mongodb-org -y |& tee -a $LOG
                systemctl start mongod.service |& tee -a $LOG
                systemctl enable mongod.service |& tee -a $LOG
                echo "MongoDB Version Detail" |& tee -a $LOG
                echo "$(mongod --version)" |& tee -a $LOG
                fi
        else
        echo "Mongo Repo Exist" |& tee -a $LOG
fi
echo "[centrifugo] Preparing" |& tee -a $LOG
if systemctl list-units | grep 'centrifugo.service'; then
  echo "[centrifugo] Already installed & configured, exiting....!!!" |& tee -a $LOG
else
  echo "[centrifugo] Adding repositories" |& tee -a $LOG
  curl -s https://packagecloud.io/install/repositories/FZambia/centrifugo/script.rpm.sh | bash |& tee -a $LOG

  yum install -y centrifugo-2.2.2-0.x86_64 |& tee -a $LOG
  echo "[centrifugo] Installed" |& tee -a $LOG
echo '{
  "port": "9000",
  "admin": true,
  "secret": "215ae26c-5c17-4ed2-8200-77f61d5b3a27",
  "admin_password": "f4d83191-271f-4299-88cb-b1a52da2cbf6",
  "admin_secret": "58e2eb05-0d96-453e-8cf1-968c8daf8d1c",
  "api_key": "7682edc6-3a4e-4464-9532-b8df5e83d252",
  "presence": true,
  "join_leave": true,
  "namespaces": [
    {
      "name": "interaction",
      "presence": true,
      "join_leave": true
    },
    {
      "name":"notifications"
    },
    {
      "name":"chatpresence",
      "presence": true,
      "join_leave": true
    }

  ]
}' > /etc/centrifugo/config.json
systemctl restart centrifugo
fi
echo "[centrifugo] Done" |& tee -a $LOG
}

function git_cx9() {
if [ -f /tmp/code ]; then
echo "Source code is already downlload"
else
cd /etc/ && git clone https://$u:$p@$d/root/agispeedy-7.1.x.git agispeedy &\
cd /etc/ && git clone https://$u:$p@$d/habibshahid/node.git node  &\
cd / && git clone https://$u:$p@$d/cicd/scripts.git &\
cd /var/www/html/ && git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/abdullah-manzoor/asterisk_intellicon.git intellicon_asterisk & \
cd /etc && git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/intellicon_contegris/iwgw.git & \
cd /var/www/html/ && git clone https://$u:$p@$d/intellicon-x9/intellicon-production.git intellicon
mkdir /root/cx9
cd /root/cx9/ && git clone https://$u:$p@$d/cx9-production/cx9-ui-production.git ui
cd /root/cx9/ && git clone https://$u:$p@$d/cx9-production/cx9-servers-production.git cx9-servers
echo "Git clone done"
echo "Please wait setting up the code"
chmod 777 /scripts/*
chmod 755 -R /var/www/html/intellicon
chmod 777 -R /var/www/html/intellicon/sounds
chmod 777 -R /var/www/html/intellicon/export
ln -s /var/spool/asterisk/monitor /var/www/html/intellicon/sounds
ln -s /var/spool/asterisk/voicemail /var/www/html/intellicon/sounds
chown -R apache:apache /var/www/html/intellicon
mkdir /var/www/html/cx9
touch /tmp/code
yes | cp -a /root/cx9/ui/build/* /var/www/html/cx9 && echo "UI Code has been copied Successfully"
fi

if test -d "/etc/asterisk" ; then 
        yes | cp -pf /var/www/html/intellicon_asterisk/*  /etc/asterisk && ls /etc/asterisk  |& tee -a $LOG
        echo "Asterisk Configuration files are copied successfully"
        chmod 777 /etc/asterisk/sip_registrations.conf
fi
echo "Setting up Agispeedy"
## Agi service
if test -d "/etc/agispeedy" ; then
        chmod 755 -R /etc/agispeedy
        yes | cp /etc/agispeedy/contrib/agispeedy /etc/init.d/ && echo Agispeedy file copied successfully
        echo "We are done with Agispeedy"
fi
}

function yarn_install() {
CX9_DIR="/root/cx9/cx9-servers"
NODE_PATH=/etc/node
if [[ ! -L /usr/local/bin/yarn ]]; then
        bash /tmp/npm1 |& tee -a $LOG
        yarn -v
        else
        echo "Yarn is already installed and version is $(yarn -v)"
fi

if [ -d $CX9_DIR ]; then
        cd $CX9_DIR && bash /tmp/npm3 |& tee -a $LOG
        else
        echo $CX9_DIR not found
        exit 1
fi

if [ -d $NODE_PATH ]; then
        cd $NODE_PATH && bash /tmp/npm2 |& tee -a $LOG
        else
        echo $NODE_PATH not found
        exit 1
fi
}

function redis_config() {
REDIS_CONFIG_FILE="/etc/redis.conf"
clear
echo "Redis Configuration"
sleep 1
sed -i -e 's/# requirepass foobared/requirepass intelliR3d!$/g' $REDIS_CONFIG_FILE
sed -i -e 's/notify-keyspace-events ""/notify-keyspace-events "Ex"/g' $REDIS_CONFIG_FILE
echo "Redis configuration has been done"
PHP_INI="/etc/php.ini"
ZEND_NAME="zend_extension = /usr/lib64/ioncube_loader_lin_7.1.so"
ZEND_FILE="/var/www/html/ssl/ioncube_loader_lin_7.1.so"
ZEND_PATH="/usr/lib64"
#FILE_LINK=$(cat /etc/php.ini | grep "zend_extension = /usr/lib64/ioncube_loader_lin_7.1.so")
echo "PHP Configuration"
sed -i -e 's/memory_limit = 128M/memory_limit = 4096M/g' $PHP_INI
sed -i -e 's/upload_max_filesize = 2M/upload_max_filesize = 50M/g' $PHP_INI
echo "PHP Configuration has been done"
if (( $(cat /etc/php.ini | grep -i 'zend_extension = /usr/lib64/ioncube_loader_lin_7.1.so' | wc -l) == 1 )); then
echo "Zend Extension has been added in PHP.ini file"
else
echo  $ZEND_NAME >> $PHP_INI
echo "Zend file extensions added in PHP configuration file"
fi
echo "Coping the ioncube_loader_lin_7 for php"
yes | cp $ZEND_FILE  $ZEND_PATH && chmod 755 $ZEND_PATH/ioncube_loader_lin_7.1.so  |& tee -a $LOG
echo "ioncube_loader_lin_7 file has been copied successfully"
REDIS_PASSWORD=$(cat /etc/redis.conf | grep "requirepass intelliR" | awk '{print $2}')
MEMORY_LIMIT=$(cat /etc/php.ini | grep "memory_limit = 4096M")
UPLOAD_MAX_FILESIZE=$(cat /etc/php.ini | grep "upload_max_filesize = 50M")

##### PHP FPM CONFIGURATION #####
PHP_FPM="/etc/php-fpm.d/www.conf"
sed -i -e 's/9000/9999/g' $PHP_FPM

clear
echo "Below is the Redis and PHP configuation"
echo
echo
echo
echo "Redis Password                            :               $REDIS_PASSWORD"
echo "PHP Memory Limit                          :               $MEMORY_LIMIT"
echo "PHP Upload File Size                      :               $UPLOAD_MAX_FILESIZE"
echo "PHP Zend File Link                        :               `cat /etc/php.ini | grep "zend_extension = /usr/lib64/ioncube_loader_lin_7.1.so"`"
echo "PHP FPM Port Settings                     :               `cat /etc/php-fpm.d/www.conf | grep 9999`"
sleep 3
}

function httpd_config_intellicon() {

HTTPD_CONFIG_FILE="/etc/httpd/conf/httpd.conf"
HTACCESS_FILE=".htaccess"
HTACCESS_PATH="/var/www/html"
WRITE_HT="/var/www/html/.htaccess"
PROXY_PATH="/etc/httpd/conf.d"
PROXY_FILE="proxy.conf"
PROXY_OLD="$PROXY_PATH/$PROXY_FILE"
#create vi /etc/httpd/conf.d/proxy.conf and add the following lines

echo "Checking for wget..."
if ! type "httpd" > /dev/null 2>&1; then
echo "Httpd is not installed, installing" |& tee -a $LOG
sleep 2
yum --assumeyes install wget |& tee -a $LOG
fi
echo "Wget is installed and functioning" |& tee -a $LOG

if [ -f $PROXY_PATH/$PROXY_FILE ]; then
echo "File already exist"
else
cd $PROXY_PATH && touch $PROXY_FILE 
echo  "<IfModule mod_proxy.c>
                ProxyRequests Off
                        <Proxy *>
                                Order deny,allow
                                Allow from all
                        </Proxy>                       
# destination server and directory
ProxyPass /intellicon/intelli-Ajam http://localhost:8088/intelli-Ajam
</IfModule>" >> $PROXY_PATH/$PROXY_FILE |& tee -a $LOG
fi

HTACCESS_OLD="$HTACCESS_PATH/$HTACCESS_FILE"
if [ -f $HTACCESS_PATH/$HTACCESS_FILE ]; then
echo "File already exist"
else
cd $HTACCESS_PATH && touch $HTACCESS_FILE |& tee -a $LOG
echo "RewriteEngine On
RewriteRule ^$ /intellicon [L] " > $WRITE_HT |& tee -a $LOG
fi

if [[ -f /etc/httpd/conf/httpd.conf ]]; then
echo "Intellicon Directory in httpd.conf is already exist"
else
echo "
<Directory "/var/www/html/intellicon">
        Options FollowSymLinks
        AllowOverride All
        Order allow,deny
        Allow from all
</Directory>" >> /etc/httpd/conf/httpd.conf
touch /tmp/http  |& tee -a $LOG
sed -i -e 's/Options Indexes FollowSymLinks/Options FollowSymLinks/g' /etc/httpd/conf/httpd.conf  |& tee -a $LOG
fi

if test -f "/tmp/sudoersfile" ; then
        echo Apache Permissions are already set in Sudoers
else
        echo 'apache ALL=(ALL)      NOPASSWD: ALL' >> /etc/sudoers
        echo Apache Permissions has been set
        touch /tmp/sudoersfile
fi
}

function htaccess_cx9() {
cx9_htaccess=/var/www/html/cx9
if [[ -d $cx9_htaccess ]] || [[ -f $cx9_htaccess/.htaccess ]]; then
echo "Htaccess file exist under the cx9 Directory."
else
mkdir $cx9_htaccess
touch $cx9_htaccess/.htaccess
echo '<ifModule mod_gzip.c>
mod_gzip_on Yes
mod_gzip_dechunk Yes
mod_gzip_item_include file .(html?|txt|css|js|php|pl)$
mod_gzip_item_include handler ^cgi-script$
mod_gzip_item_include mime ^text/.*
mod_gzip_item_include mime ^application/x-javascript.*
mod_gzip_item_exclude mime ^image/.*
mod_gzip_item_exclude rspheader ^Content-Encoding:.*gzip.*
</ifModule>
# BEGIN GZIP
<IfModule mod_deflate.c>
  # Compress HTML, CSS, JavaScript, Text, XML and fonts
  AddOutputFilterByType DEFLATE application/javascript
  AddOutputFilterByType DEFLATE application/rss+xml
  AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
  AddOutputFilterByType DEFLATE application/x-font
  AddOutputFilterByType DEFLATE application/x-font-opentype
  AddOutputFilterByType DEFLATE application/x-font-otf
  AddOutputFilterByType DEFLATE application/x-font-truetype
  AddOutputFilterByType DEFLATE application/x-font-ttf
  AddOutputFilterByType DEFLATE application/x-javascript
  AddOutputFilterByType DEFLATE application/xhtml+xml
  AddOutputFilterByType DEFLATE application/xml
  AddOutputFilterByType DEFLATE font/opentype
  AddOutputFilterByType DEFLATE font/otf
  AddOutputFilterByType DEFLATE font/ttf
  AddOutputFilterByType DEFLATE image/svg+xml
  AddOutputFilterByType DEFLATE image/x-icon
  AddOutputFilterByType DEFLATE text/css
  AddOutputFilterByType DEFLATE text/html
  AddOutputFilterByType DEFLATE text/javascript
  AddOutputFilterByType DEFLATE text/plain
  AddOutputFilterByType DEFLATE text/xml
</IfModule>
# END GZIP
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301,NE]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.html [PT,L]'> $cx9_htaccess/.htaccess
echo "CX9 redirect file has been created successfully"
fi
}

function cronjob() {

if [ -d /var/local/startup_scripts ]; then 
echo "Startup Scripts are already downloaded"
else
cd /var/local/ && git clone https://abdullah-manzoor:Abdu11ah\!\%\!\%\!\%\@bitbucket.org/abdullah-manzoor/startup_scripts.git  startup_scripts
cp /var/local/startup_scripts/*  /var/local
chmod 755 /var/local/*
echo "Startup Scripts have been donwloaded successfully"
fi

if [ -f /var/local/intellicon_cron ]; then
echo "Cron Job file already exist"
else
touch   /var/local/intellicon_cron 
echo '*/10 * * * * /usr/sbin/ntpdate
@reboot cd /root/cx9/cx9-servers && /usr/local/bin/pm2 start ecosystem.config.js >> /var/local/srvscript.log
@reboot cd /etc/node && /usr/local/bin/node starter.js >> /var/local/srvscript.log
*/1 * * * * /var/local/turn.sh >> /var/local/srvscript.log
0 0 * * * /usr/sbin/asterisk -rx "logger rotate" >> /var/local/srvscript.log
0 0 1 * * /var/local/log_delete.sh >> /var/local/srvscript.log
*/5 * * * * /usr/bin/curl http://127.0.0.1/intellicon-dev/dialerOnly/dialerFiles > /var/log/intellicon/intellicon_dialer_cron.log' >> /var/local/intellicon_cron
echo "Cronjob Setting has been done."
fi
touch /var/local/srvscript.log
crontab /var/local/intellicon_cron

}


#------------------------------------------------------- At the end of script ----------------------------------------------
function install_pci(){

# MOD_SECURITY Variables
REMOVE_MOD_SECURITY=mod_security
MOD_SECURITY_LINK=https://github.com/SpiderLabs/ModSecurity/releases/download/v2.9.1/modsecurity-2.9.1.tar.gz
MOD_SECURITY_PKG=modsecurity-2.9.1.tar.gz
MOD_SECURITY_DIR=(modsecurity-*)

echo "##COMPILE AND INSTALL MOD_SECURITY (PCI)#"  |& tee -a $LOG
echo ""  |& tee -a $LOG

yum --assumeyes remove $REMOVE_MOD_SECURITY |& tee -a $LOG
wget --progress=bar:force $MOD_SECURITY_LINK 2>&1 | while read -d "%" X; do sed 's:^.*[^0-9]\([0-9]*\)$:\1:' <<< "$X"; done | dialog --backtitle "${BACKTITLE}" --title "${MOD_SECURITY_PKG}"  --gauge "Downloading from ${MOD_SECURITY_LINK}..." 20 70
if [ $? -ne 0 ]
then
echo 1>&2 $0: "$MOD_SECURITY_LINK is not responding at this time try again...!"  Exiting.
exit 1
else
echo "Successfully downlload MOD_SECURITY"  |& tee -a $LOG
fi

tar -xzf $MOD_SECURITY_PKG && rm -rf $MOD_SECURITY_PKG && cd $MOD_SECURITY_DIR

PCI_CONFIGURE='./configure'
$PCI_CONFIGURE |& tee -a $LOG

if [ $? -ne 0 ]
then
echo 1>&2 $0: "$PCI_CONFIGURE"  Exiting.
exit 1
else
echo "Successfully configured MOD_SECURITY"  |& tee -a $LOG
fi

PCI_MAKE='make'
make |& tee -a $LOG

if [ $? -ne 0 ]
then
# ./make had problems.
echo 1>&2 $0: "$PCI_MAKE"  Exiting.
exit 1
else
echo "MOD_SECURITY successfully installed"  |& tee -a $LOG
fi

PCI_MAKE_IN='make install'
$PCI_MAKE_IN |& tee -a $LOG

# OWASP Variables
OWASP_CHANGE="/etc/httpd"
#OWASP_LINK=https://github.com/SpiderLabs/owasp-modsecurity-crs.git
OWASP_LINK="https://github.com/SpiderLabs/owasp-modsecurity-crs.git"
OWASP_DIR=owasp-modsecurity-crs
OWASP_CONF_EXAMPLE=crs-setup.conf.example
OWASP_CONF_FILE=modsecurity_crs_10_config.conf

cd $OWASP_CHANGE
#rm -rf /etc/httpd/owasp-modsecurity-crs
#yum update -y nss curl libcurl
#git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git |& tee -a $LOG
#if [ $? != 0 ]; then
#echo "OWASP not downloaded successfully"
#else
#       echo "Updating NSS & CURL"
#       yum update -y nss curl libcurl
#       git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git |& tee -a $LOG
#fi
echo "$OWASP_DIR successfully downloaded"  |& tee -a $LOG
cd $OWASP_DIR && yes | cp  $OWASP_CONF_EXAMPLE  $OWASP_CONF_FILE && echo "File has been copied"  |& tee -a $LOG


APACHE_KEY="/etc/pki/tls/private/apache-selfsigned.key"
APACHE_CRT="/etc/pki/tls/certs/apache-selfsigned.crt"

if [ -f $APACHE_CRT ]; then
echo "selfsigned certificate is already exist"
else
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/pki/tls/private/apache-selfsigned.key -out /etc/pki/tls/certs/apache-selfsigned.crt <<EOF ##|& tee -a $LOG | dialog --title "Run openssl install. Please Wait.." --backtitle "INTELLICON Starter Script By Contegris" --progressbox 30 100







EOF
openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 2048 |& tee -a $LOG
fi

}

function db_setting() {
#auto passwrod generator
#strings /dev/urandom | grep -o '[.[:alnum:]]+$' | head -n 6 | tr -d '\n' > password
if [ -f /root/my.cnf ];then
        echo "SQL PASSWORD is already set and PASSWORD is: $(cat /root/my.cnf)"
else
        systemctl start mysqld && sleep 1

MYSQL_ROOT=root
root_pass_db=`cat /var/log/mysqld.log | grep -i 'temporary password' | cut  -d ' ' -f11` 

echo $root_pass_db > /root/my.cnf
#echo "[client]
#user=root
#password=$root_pass_db" > /root/.my.cnf && chmod 600 /root/.my.cnf

touch /etc/my.cnf.d/gloabals.cnf
echo '[mysqld]
sql_mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
validate_password_mixed_case_count      =       0
validate_password_number_count          =       0
validate_password_special_char_count    =       0
max_connections = 500' > /etc/my.cnf.d/gloabals.cnf
systemctl restart mysqld && sleep 1

mysql -u "$MYSQL_ROOT" --password=$root_pass_db --connect-expired-password -e "SET PASSWORD FOR root@'localhost' = PASSWORD('"$root_pass_db"');"
mysql -u "$MYSQL_ROOT" --password=$root_pass_db -e "show databases;"

#systemctl set-environment MYSQLD_OPTS="--skip-grant-tables"
#systemctl unset-environment MYSQLD_OPTS
## Can check the ping from Database (mysqladmin ping -u root --password='$PASSWORD')
fi

PASSWORD_MYSQL=$(cat /root/my.cnf)

echo "
--------------------------------------------------------------------------------
################################################################################
#                     Setting UP DB Dump                                       #
################################################################################
--------------------------------------------------------------------------------"
sleep 3
if [ -f /tmp/db_created ]; then
echo "Intellicon DB is already exist"  |& tee -a $LOG
sleep 2
else
  mysql -u "$MYSQL_ROOT" --password=$PASSWORD_MYSQL < /var/www/html/intellicon/database/yovo_db_cc.sql
  mysql -u "$MYSQL_ROOT" --password=$PASSWORD_MYSQL < /var/www/html/intellicon/database/yovo_db_cc_ast.sql
  mysql -u "$MYSQL_ROOT" --password=$PASSWORD_MYSQL < /etc/iwgw/opensips.sql
  mysql -u "$MYSQL_ROOT" --password=$PASSWORD_MYSQL < /var/www/html/intellicon/database/users.sql
  touch /tmp/db_created
  echo "Intellicon Database has been created successfully"  |& tee -a $LOG
fi
}

function start_services() {

systemctl enable opensips
if [[ $? == 0 ]] ; then
  echo "[opensips] Service Enabled on Boot, exiting....!!!"
else
  echo "[opensips] is not installed"
fi

systemctl enable firewalld
if [[ $? == 0 ]] ; then
  echo "[firewalld] Service Enabled on Boot, exiting....!!!"
else
  echo "[firewalld] is not installed"
fi

systemctl enable rabbitmq-server
if [[ $? == 0 ]] ; then
  echo "[rabbitmq-server] Service Enabled on Boot, exiting....!!!"
else
  echo "[rabbitmq-server] is not installed"
fi

systemctl enable nginx
if [[ $? == 0 ]] ; then
  echo "[nginx] Service Enabled on Boot, exiting....!!!"
else
  echo "[nginx] is not installed"
fi

systemctl enable redis
if [[ $? == 0 ]] ; then
  echo "[redis] Service Enabled on Boot, exiting....!!!"
else
  echo "[redis] is not installed"
fi

systemctl enable vmtoolsd
if [[ $? == 0 ]] ; then
  echo "[vmtoolsd] Service Enabled on Boot, exiting....!!!"
else
  echo "[vmtoolsd] is not installed"
fi

systemctl enable rtpengine
if [[ $? == 0 ]] ; then
  echo "[rtpengine] Service Enabled on Boot, exiting....!!!"
else
  echo "[rtpengine] is not installed"
fi

systemctl enable asterisk
if [[ $? == 0 ]] ; then
  echo "[asterisk] Service Enabled on Boot, exiting....!!!"
else
  echo "[Asterisk] is a native Service Using the chkconfig command"
  chkconfig asterisk on
fi

systemctl enable agispeedy
if [[ $? == 0 ]] ; then
  echo "[agispeedy] Service Enabled on Boot, exiting....!!!"
else
  echo "[agispeedy] is a native Service Using the chkconfig command"
  chkconfig agispeedy on
fi

systemctl enable fail2ban
if [[ $? == 0 ]] ; then
  echo "[fail2ban] Service Enabled on Boot, exiting....!!!"
else
  echo "[fail2ban] is not installed"
fi

systemctl enable mysqld
if [[ $? == 0 ]] ; then
  echo "[mysqld] Service Enabled on Boot, exiting....!!!"
else
  echo "[mysqld] is not installed"
fi

systemctl enable mongod
if [[ $? == 0 ]] ; then
  echo "[mondod] Service Enabled on Boot, exiting....!!!"
else
  echo "[mondod] is not installed"
fi

systemctl enable httpd
if [[ $? == 0 ]] ; then
  echo "[httpd] Service Enabled on Boot, exiting....!!!"
else
  echo "[httpd] is not installed"
fi

systemctl enable php-fpm
if [[ $? == 0 ]] ; then
  echo "[httpd] Service Enabled on Boot, exiting....!!!"
else
  echo "[httpd] is not installed"
fi

systemctl enable firewalld
if [[ $? == 0 ]] ; then
   systemctl start firewalld
     if [[ $? == 0 ]] ; then
        echo "Firewalld service has been started & Enabled on Startup"
        firewall-cmd --permanent --add-port=22/tcp | echo Port [22/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=58779/tcp | echo Port [58779/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=443/tcp | echo Port [443/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=995/tcp | echo Port [995/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=993/tcp | echo Port [993/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=4443/tcp | echo Port [4443/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=4001/tcp | echo Port [4001/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=4002/tcp | echo Port [4002/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=8443/tcp | echo Port [8443/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=10443/tcp | echo Port [10443/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=15672/tcp | echo Port [15672/TCP] has been added in Firewall Rule
        firewall-cmd --permanent --add-port=10000-20000/udp | echo Port [10000-20000/UDP] has been added in Firewall Rule
        firewall-cmd --reload
     else
        echo "Firewalld Not Running Please check it Manually"
     fi
else
  echo Unable to Enabled Firewalld
fi
}

function opensips() {
echo "
--------------------------------------------------------------------------------
################################################################################
#                     Setup OpenSIPs Repo for Cent OS 7                        #
################################################################################
--------------------------------------------------------------------------------"
#OPENSIPS="yum install -y http://yum.opensips.org/2.4/releases/el/7/x86_64/opensips-yum-releases-2.4-3.el7.noarch.rpm"
OPENSIPS="yum install -y https://yum.opensips.org/2.4/releases/el/7/x86_64/opensips-yum-releases-2.4-6.el7.noarch.rpm"

if [ -f /tmp/opensips ]; then
echo "Nothing to do"
else
$OPENSIPS
touch /tmp/opensips
fi
RPM_GPG_KEY="sudo rpm --import http://li.nux.ro/download/nux/RPM-GPG-KEY-nux.ro"
############## For Centos 7 ###############
NUX_DEXTOP="sudo rpm -Uvh http://li.nux.ro/download/nux/dextop/el7/x86_64/nux-dextop-release-0-5.el7.nux.noarch.rpm"
############## For Centos 6 ###############
#sudo rpm -Uvh http://li.nux.ro/download/nux/dextop/el6/x86_64/nux-dextop-release-0-2.el6.nux.noarch.rpm

if [ -f /tmp/nux_dextop ]; then
echo "Nothing to do"
else
$RPM_GPG_KEY
$NUX_DEXTOP
touch /tmp/nux_dextop
fi


echo "
--------------------------------------------------------------------------------
################################################################################
#                            Install OpenSIPs                                  #
################################################################################
--------------------------------------------------------------------------------"
if [ -f /tmp/packages_opensips ]; then
echo "Nothing to do"
else
#if Cent OS 7
yum install -y hiredis hiredis-devel libpcap-devel libevent libevent-devel gperf
yum install -y glib glib-devel gcc zlib zlib-devel openssl openssl-devel pcre pcre-devel libcurl libcurl-devel xmlrpc-c xmlrpc-c-devel
yum install -y pkgconfig.x86_64 glib2-devel.x86_64 json-glib json-glib-devel zlib-devel.x86_64 xmlrpc-c-devel.x86_64 libcurl.x86_64 iptables-devel.x86_64 kernel-headers.x86_64 kernel-devel.x86_64
yum install -y iptables-devel kernel-devel kernel-headers xmlrpc-c-devel
yum install libevent-devel glib2-devel json-glib-devel gperf libpcap-devel git hiredis hiredis-devel perl-IPC-Cmd -y
yum install -y "kernel-devel-uname-r == $(uname -r)"
yum install -y ffmpeg ffmpeg-devel
#yum update -y perl*
yum install perl-IPC-Cmd -y
#yum install -y opensips opensips-db_mysql.x86_64 opensips-mid_registrar.x86_64 opensips-rtpengine.x86_64 opensips-proto_wss.x86_64 opensips-proto_ws.x86_64 opensips-proto_tls.x86_64 opensips-tls_mgm.x86_64 
yum install -y opensips-2.4.3-1.el7.x86_64 opensips-proto_wss-2.4.3-1.el7.x86_64 opensips-tls_mgm-2.4.3-1.el7.x86_64 opensips-db_mysql-2.4.3-1.el7.x86_64 opensips-proto_tls-2.4.3-1.el7.x86_64 opensips-proto_ws-2.4.3-1.el7.x86_64 opensips-mid_registrar-2.4.3-1.el7.x86_64 opensips-rtpengine-2.4.3-1.el7.x86_64
############## For Centos 6 ###############
#yum install -y opensips-2.4.3-1.el6.x86_64 opensips-proto_wss-2.4.3-1.el6.x86_64 opensips-tls_mgm-2.4.3-1.el6.x86_64 opensips-db_mysql-2.4.3-1.el6.x86_64 opensips-proto_tls-2.4.3-1.el6.x86_64 opensips-proto_ws-2.4.3-1.el6.x86_64 opensips-mid_registrar-2.4.3-1.el6.x86_64 opensips-rtpengine-2.4.3-1.el6.x86_64
touch /tmp/packages
fi

#opensipsdbctl create
#CREATE DATABASE opensips;
#CREATE USER 'opensips'@'localhost' IDENTIFIED BY 'opensipsrw';
#GRANT ALL PRIVILEGES ON opensip.* TO 'opensips'@'localhost';
#mysql -uroot -p opensips < /etc/opensips/iwgw/opensips.sql
if [ -f /tmp/opensip_conf ]; then
echo "OPENSIPS configuation file is already coppied"
else
yes | cp /etc/iwgw/opensips.cfg  /etc/opensips/ && echo "File has been copied"
IPADDRESS=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
sed -i -e "s/IPADDRESS/$IPADDRESS/g" /etc/opensips/opensips.cfg
mysql -uopensips -popensipsrw -e "update opensips.dispatcher set destination = 'sip:"$IPADDRESS":5060', socket = 'udp:"$IPADDRESS":6060' where setid = 4002;"
touch /tmp/opensip_conf
echo "opensips.cfg has been coppied successfully"
fi

}

function rtp_engine(){
echo "
--------------------------------------------------------------------------------
################################################################################
#                                 Install RTP Engine                           #
################################################################################
--------------------------------------------------------------------------------"
if [ -d /usr/local/src/downloads ]; then
echo "Directory exist"
else
mkdir /usr/local/src/downloads
fi

if [ -d /usr/local/src/downloads/rtpengine ]; then
echo "Rtpengine Directory exist"
else
cd /usr/local/src/downloads
git clone https://git.contegris.com/root/rtpengine.git
#git clone https://github.com/sipwise/rtpengine.git
fi

if [ -f /tmp/make ]; then
echo "Configured"
else
cd /usr/local/src/downloads/rtpengine/daemon/
make
ln -s /usr/local/src/downloads/rtpengine/daemon/rtpengine /usr/sbin/
cd ../iptables-extension/
make
cp libxt_RTPENGINE.so /lib64/xtables/
cd ../kernel-module/
make
touch /tmp/make
fi
if [ -d /etc/rtpengine ]; then
echo "Rtpengine Directory already exist"
else
mkdir /etc/rtpengine
cp /etc/iwgw/rtpengine.conf  /etc/rtpengine
IPADDRESS=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
sed -i -e "s/IPADDRESS/$IPADDRESS/g" /etc/rtpengine/rtpengine.conf
echo "rtpengine.conf file has been coppied successfully"
fi
#cp xt_RTPENGINE.ko /lib/modules/$(uname -r)/
#cp xt_RTPENGINE.ko /lib/modules/$(uname -r)/updates/
cd /lib/modules/
ls -1 | while read d
do
    test -d "$d" || continue
    echo $d
    (cd $d ;
yes | cp /usr/local/src/downloads/rtpengine/kernel-module/xt_RTPENGINE.ko .   && ls /lib/modules
echo "File has been coppied successfully"
echo "In ${PWD}")
done
depmod -a
modprobe xt_RTPENGINE
lsmod | grep -i xt_RTPENGINE

#to remove rmmod xt_RTPENGINE
#For CentOS7 Create service file under the directory
touch /usr/lib/systemd/system/rtpengine.service

echo '[Unit]
Description=Kernel based rtp proxy
After=syslog.target
After=network.target

[Service]
Type=forking
PIDFile=/var/run/rtpengine.pid
EnvironmentFile=-/etc/rtpengine/rtpengine.conf
ExecStart=/usr/sbin/rtpengine -p /var/run/rtpengine.pid 

Restart=always

[Install]
WantedBy=multi-user.target' >  /usr/lib/systemd/system/rtpengine.service

if [ -x /etc/modules-load.d/xt_RTPENGINE.conf ]; then
echo "Rtpengine module file exist"
else
touch /etc/modules-load.d/xt_RTPENGINE.conf
echo "#Load Module of RTPENGINE on machine startup
xt_RTPENGINE" > /etc/modules-load.d/xt_RTPENGINE.conf && chmod 755 /etc/modules-load.d/xt_RTPENGINE.conf
echo "Rtpengine startup module loaded file has been created"
fi

#/usr/sbin/rtpengine -f -E --pidfile /var/run/ngcp-rtpengine-daemon.pid --config-file /etc/rtpengine/rtpengine.conf --table 0
}

function rabbitmq() {
#Centos 7
#ERLANG="rpm -Uvh https://github.com/rabbitmq/erlang-rpm/releases/download/v20.3.8.9/erlang-20.3.8.9-1.el7.centos.x86_64.rpm"
#ERLANG="rpm -Uvh https://bintray.com/rabbitmq-erlang/rpm/download_file?file_path=erlang%2F21%2Fel%2F7%2Fx86_64%2Ferlang-21.3-1.el7.x86_64.rpm"
ERLANG="wget https://packages.erlang-solutions.com/erlang-solutions-1.0-1.noarch.rpm"
if [ -f /etc/yum.repos.d/erlang_solutions.repo ]; then
        echo "Rabbitmq repo is already exist"
else
        $ERLANG
        rpm -Uvh erlang-solutions-1.0-1.noarch.rpm
        echo "Erlang Repository has been added"
        yum install -y erlang
fi

if [ -f /tmp/rabbitmq ]; then
        echo "Rebbitmq Package is already installed"
        else
#       rpm --import https://www.rabbitmq.com/rabbitmq-release-signing-key.asc
        yum install socat logrotate -y
#       yum install -y https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.8.16/rabbitmq-server-3.8.16-1.el7.noarch.rpm
#       service rabbitmq-server start
#       systemctl enable rabbitmq-server
SERVICE=$(systemctl status rabbitmq-server | grep active | awk '{print $2}')
        if [ $SERVICE == active ]; then
                rabbitmq-plugins enable rabbitmq_management
                echo "Rabbitmq plugins has been enabled successfully"
                rabbitmqctl add_user admin contegris
                echo "Rabbitmq Admin user has been created successfully"
                rabbitmqctl set_user_tags admin administrator
                echo "Rabbitmq Admin user tag has been created successfully"
                rabbitmqctl add_user intellicon intellicon
                echo "Rabbitmq Admin user intellicon has been created successfully"
                rabbitmqctl set_user_tags intellicon administrator
                echo "Rabbitmq Admin user intellicon tag has been created successfully"
                rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"
                echo "Rabbitmq Admin User permission has been set successfully"
                rabbitmqctl set_permissions -p / intellicon ".*" ".*" ".*" 
                echo "Rabbitmq Admin User intellicon permission has been set successfully"
                touch /tmp/rabbit
        else
                echo "Rabbitmq service is not running"
                exit
        fi
touch /tmp/rabbitmq
fi
}

function ssl_config() {

if [ -d /var/www/html/ssl ]; then
echo
else
cd /var/www/html && git clone https://$u:$p@$d/root/certs_contegris.git ssl |& tee -a $LOG
fi

if [ -d /var/www/html/ssl ]; then
yes | cp /var/www/html/ssl/certs/*  /etc/pki/tls/certs/ && echo  "Contegris Domain File has been copied"  |& tee -a $LOG
yes | cp /var/www/html/ssl/private/*    /etc/pki/tls/private/ && echo  "Key File has been copied"  |& tee -a $LOG
yes | cp /var/www/html/ssl/ssl/*    /etc/httpd/conf.d/  && echo  "SSL.conf File has been copied"  |& tee -a $LOG
yes | cp /var/www/html/ssl/httpd/*   /etc/httpd/conf/   && echo  "HTTP config File has been copied"  |& tee -a $LOG
yes | cp /var/www/html/ssl/nginx/*   /etc/nginx/  && echo  "File has been copied"  |& tee -a $LOG
yes | cp /var/www/html/ssl/ioncube_loader_lin_7.1.so /usr/lib64/ && chmod 777 /usr/lib64/ioncube_loader_lin_7 && echo "PHP Encryption File has been copied"  |& tee -a $LOG
ls /etc/pki/tls/certs |& tee -a $LOG
ls /etc/pki/tls/private  |& tee -a $LOG
ls /etc/httpd/conf.d |& tee -a $LOG
ls /etc/httpd/conf |& tee -a $LOG
ls /etc/nginx |& tee -a $LOG
else
echo "SSL Directory not exist"
fi

#How to generate CSR File start with ++++++ Begin Certificate Request +++++++++++
#openssl req -new -newkey rsa:2048 -nodes -out star_finca_org_pk.csr -keyout star_finca_org_pk.key -subj "/C=PK/ST=Punjab/L=Lahore/O=FINCA Microfinance Bank LTd/OU=IT/CN=*.finca.org.pk"
#openssl req -new -newkey rsa:2048 -nodes -out CRM_SSCBrands_local.csr -keyout CRM_SSCBrands_local.key -subj "/C=PK/ST=Punjab/L=Lahore/O=SSC Brands/OU=IT/CN=crm.sscbrands.local"
# remove the password from ssl : openssl rsa -in key.pem -out newkey.pem
#openssl pkcs12 -in <filename>.pfx  -nocerts -out key.pem
#To extract the certificate (public key), run the OpenSSL command:
#openssl pkcs12 -in <filename>.pfx -clcerts -nokeys -out cert.pem
#openssl req -new -newkey rsa:2048 -nodes -out your-domain.csr       -keyout your-domain.key
# .pem to crt
#openssl x509  -in fullchain.pem  -out cert.crt
#key.pem to .key
#openssl rsa -in privkey.pem -out private.key
}

function post_install(){
var="'base_country'"
echo '#!/bin/bash
set -e
set pipefail
flag=true

function runmigration(){
        flag=true
        mysql -uintellicon --password=intellicon -e "delete from yovo_db_cc.yovo_tbl_settings where meta_key='$var';" && \
        cd /root/cx9/cx9-servers/cx9-migrations  &&  \
        npx sequelize db:migrate:status --config config/index.js --env mysql && \
        cd /root/cx9/cx9-servers/cx9-migrations  &&  \
        npx sequelize db:migrate --config config/index.js --env mysql && \
        sleep 2 && \
        cd /root/cx9/cx9-servers/cx9-migrations  &&  \
        npx sequelize db:migrate:status --config config/index.js --env mysql && \
        sleep 10 && \
        cd /root/cx9/cx9-servers/cx9-migrations  &&  \
        npx sequelize db:seed:all --config config/index.js --env mysql

}

function get_UUID(){
UUID=`cat /sys/class/dmi/id/product_uuid`
read -rp "Please type your Email for System UUID : " -e EMAIL
printf "UUID of System \nHostname: $HOSTNAME \nUUID: $UUID" | mail $EMAIL 
}

sleep 5
#start_services
echo "******************** Running runmigration this function"
runmigration
sleep 2
echo "******************** Generating Chatbot Build"
cd /root/cx9/cx9-servers/cx9-chatbot-widget/client && yarn install && yarn build
get_UUID
sleep 2
cd /root/cx9/cx9-servers && pm2 start ecosystem.config.js' > /var/www/html/post_install.sh && chmod 777 /var/www/html/post_install.sh
}

function get_UUID(){
UUID=`cat /sys/class/dmi/id/product_uuid`
#read -rp "Please type your Email for System UUID : " -e EMAIL
printf "UUID of System \nHostname: $HOSTNAME \nUUID: $UUID" | mail abdullah.manzoor@contegris.com
}
function install_complete() {
IPADDRESS=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
dialog --title "INTELLICON Starter Script" --backtitle "INTELLICON Starter Script \
By Contegris" --infobox "\nThanks for your time! \
\nIf you used the INTELLICON installer, \nin order to finish the installation, \nYou can access INTELLICON with these credentials, \n URL: https://"$IPADDRESS"/intellicon/wizard \nUser Name: admin@intellicon.io, \nPassword: contegris2017\n\n" 20 70 
sleep 10
clear
echo "We are going to Reboot the system"
sudo reboot
}
function exit_status() {
dialog --title "INTELLICON Starter Script" --backtitle "INTELLICON Starter Script \
By Contegris" --infobox "\nThanks for your time! \
\n \nExiting..........!\n\n" 20 70 
sleep 1
exit
clear
}
function install_complete_org() {
while true
do

dialog --title "INTELLICON Starter Script" --backtitle "INTELLICON Starter Script \
By Contegris" --infobox "\nThanks for your time! \
\nIf you used the INTELLICON installer, \nin order to finish the installation, \nplease reboot System!\n\n" 20 70 ; read
sleep 1
break
clear
done
}
function install_cx9(){
system_update
install_repo
install_dependecies
rabbitmq
mongodb_centrifugo
install_node
install_pm2
install_lame
install_libsrtp
install_asterisk
git_cx9
yarn_install
turnserver
db_setting
opensips
rtp_engine
ssl_config
redis_config
httpd_config_intellicon
install_pci
cronjob
fail2ban_config
post_install
start_services
get_UUID
install_complete
}

install_cx9
# if temp files found, delete em
[ -f $OUTPUT ] && rm $OUTPUT
[ -f $INPUT ] && rm $INPUT
