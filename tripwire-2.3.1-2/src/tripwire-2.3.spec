########################################################################
########################################################################
##
## Tripwire(R) 2.3 for LINUX(R) RPM Spec script
##
## Copyleft information contained in footer
##
########################################################################
########################################################################

#######################################################################
# Preamble
#######################################################################

Summary: Best of Breed integrity assessment tool.
Name: tripwire
Version: 2.3
Release: 1
Copyright: GPL
Group: Applications/System
Source: ftp://www.tripwire.org/tripwire.tar.gz
URL: http://www.tripwire.org/
Distribution: Linux
Vendor: Tripwire, Inc.
Packager: Gatekeeper <gatekeeper@tripwire.org>

%description
Tripwire 2.3 integrity assessment software is considered to be the
Best of Breed in the security market. This software creates a
cryptographically-secured database of files and their characteristics
based on the specifications of your configurable policy file. This database
is then used to determine if any unauthorized changes have been made to
your system. Tripwire software answers the fundamental question:
"Is my system the same today as it was yesterday?"

Provides: file integrity assessment

Requires: sed, grep >= 2.3, gzip, tar, gawk

ExclusiveArch: i386

ExclusiveOS: linux

BuildRoot: /usr/src/redhat/SOURCES

#######################################################################
# RPM source builder/installer
#######################################################################

%prep

%setup

%build

cd $RPM_BUILD_DIR/tripwire-2.3/src
#make distclean
cd $RPM_BUILD_DIR/tripwire-2.3/src
make release

%install

##-------------------------------------------------------
## Sanity checks, mostly stolen (with permission)
## from Larry Wall's metaconfig.
##-------------------------------------------------------

PATH='.:/bin:/usr/bin'
export PATH || (echo 'You must use sh to run this script'; kill $$)
# if [ ! -t 0 ] ; then
#        echo "Say 'sh install.sh', not 'sh < install.sh'"
#        exit 1
# fi

##-------------------------------------------------------
## Does this system have a copy of grep we can use?
## Some greps don't return status (amazing, huh?),
## so we look for a copy of grep that
## returns 0 status for an exact match
## returns 0 status for a case-insensitive match
## returns 0 status for a wildcard match
## returns non-zero status for a failed match
##-------------------------------------------------------

GREP=""
grepnames="grep egrep"
lcgrepstr="findensiemich"     # all lower case
mcgrepstr="FindenSieMich"     # mixed case
wcgrepstr="sie.ich$"          # wild card match
nogrepstr="WoBistDu"          # should not be able to find this
for p in $grepnames; do
        (echo "$lcgrepstr" | $p "$lcgrepstr") 2> /dev/null 1>&2
        if [ $? -eq 0 ]; then
                (echo "$lcgrepstr" | $p -i "$mcgrepstr") 2> /dev/null 1>&2
                if [ $? -eq 0 ]; then
                        (echo "$lcgrepstr" | $p "$wcgrepstr") 2> /dev/null 1>&2
                        if [ $? -eq 0 ]; then
                                (echo "$lcgrepstr" | $p "$nogrepstr") 2> /dev/null 1>&2
                                if [ $? -ne 0 ]; then
                                        GREP=$p
                                        break
                                fi
                        fi
                fi
        fi
done

##-------------------------------------------------------
## Does this system have a pager that we can use?
## Use cat if desperate.
##-------------------------------------------------------

MORE="cat"
morenames="more less cat"
for p in $morenames; do
        ($p $0 < /dev/null) 2> /dev/null 1>&2
        if [ $? -eq 0 ]; then
                MORE=$p
                break
        fi
done


##-------------------------------------------------------
## Miscellaneous configuration parameters.
##-------------------------------------------------------

# Which awk to use
AWK=awk

# Set main build base directory variable to reflect RPM-provided variable
BASE_DIR_NAME=$RPM_BUILD_DIR/tripwire-2.3

# Source code directory
CODE_DIR_NAME=$BASE_DIR_NAME/src

# Non-source/non-doc program-related files live here
CD_EXTRA_NAME=$BASE_DIR_NAME/policy

# Man file directory location
CD_MANUAL_NAME=$BASE_DIR_NAME/man

# Binary Build directory location
BIN_DIR_NAME=$BASE_DIR_NAME/bin/i686-pc-linux_r

# Tripwire binary
TRIPWIRE="tripwire"

# Twadmin binary
TWADMIN="twadmin"

# Twprint binary
TWPRINT="twprint"

# Siggen binary
SIGGEN="siggen"

# License File name
TWLICENSEFILE="COPYING"

# Default Tripwire configuration file.
TW_CONFIG_FILE="tw.cfg"

# Name of initial cleartext Tripwire configuration file.
CLR_CONFIG_FILE="twcfg.txt"

# Name of initial cleartext Tripwire policy file.
CLR_POLICY_FILE="twpol.txt"

# Name of the Readme file.
README="README"

# Name of the release notes.
REL_NOTES="Release_Notes"

# Starting directory.
START_DIR=`pwd`

# If prompt==true, ask for confirmation before continuing with install.
PROMPT="false"

# If CLOBBER is true, then existing files are overwritten.
# If CLOBBER is false, existing files are not overwritten.
CLOBBER=true

# Tripwire installation documents are stored in TWDOCS.
TWDOCS="/usr/doc/tripwire"

# Tripwire binaries are stored in TWBIN.
TWBIN="/usr/sbin"

# Tripwire configuration files are stored in TWCFG.
# NOTE:  If you change this variable, you will have to modify the
# program code that hard-wires the default configuration file location.
TWCFG="/etc/tripwire"

# Tripwire policy files are stored in TWPOLICY.
TWPOLICY="${TWCFG}"

# Tripwire manual pages are stored in TWMAN.
TWMAN="/usr/man"

# Tripwire database files are stored in TWDB.
TWDB="/var/lib/tripwire"

# The Tripwire site key files are stored in TWSITEKEYDIR.
TWSITEKEYDIR="${TWCFG}"

# The Tripwire local key files are stored in TWLOCALKEYDIR.
TWLOCALKEYDIR="${TWCFG}"

# Tripwire report files are stored in TWREPORT.
TWREPORT="/var/lib/tripwire/report"

# This sets the default text editor for Tripwire.
TWEDITOR="/bin/vi"

# TWLATEPROMTING controls the point when tripwire asks for a password.
TWLATEPROMPTING=false

# TWLOOSEDIRCHK selects whether the directory should be monitored for
# properties that change when files in the directory are monitored.
TWLOOSEDIRCHK=false

# TWMAILNOVIOLATIONS determines whether Tripwire sends a no violation
# report when integrity check is run with --email-report but no rule
# violations are found.  This lets the admin know that the integrity
# was run, as opposed to having failed for some reason.
TWMAILNOVIOLATIONS=true

# TWEMAILREPORTLEVEL determines the verbosity of e-mail reports.
TWEMAILREPORTLEVEL=3

# TWREPORTLEVEL determines the verbosity of report printouts.
TWREPORTLEVEL=3

# TWSYSLOG determines whether Tripwire will log events to the system log
TWSYSLOG=false

#####################################
# Mail Options - Choose the appropriate
# method and comment the other section
#####################################

#####################################
# SENDMAIL options - DEFAULT
#
# Either SENDMAIL or SMTP can be used to send reports via TWMAILMETHOD.
# Specifies which sendmail program to use.
#####################################

TWMAILMETHOD=SENDMAIL
TWMAILPROGRAM="/usr/lib/sendmail -oi -t"

#####################################
# SMTP options
#
# TWSMTPHOST selects the SMTP host to be used to send reports.
# SMTPPORT selects the SMTP port for the SMTP mail program to use.
#####################################

# TWMAILMETHOD=SMTP
# TWSMTPHOST="mail.domain.com"
# TWSMTPPORT=25

##-------------------------------------------------------
## The pathname variables we expect to find specified above
##-------------------------------------------------------

paths="TWBIN TWMAN TWPOLICY TWREPORT TWDB TWSITEKEYDIR TWLOCALKEYDIR TWCFG TWDOCS"
path2="TWBIN TWPOLICY TWREPORT TWDB TWSITEKEYDIR TWLOCALKEYDIR TWCFG"
path3="TWMAN TWDOCS TWMAN/man4 TWMAN/man8 TWMAN/man5"


##=======================================================
## Process the configuration parameters.
##=======================================================

##-------------------------------------------------------
## Value on command line, if present, overrides value in
## config file.  Value must either be "true" or "false"
## exactly; if it's not the former, make it the latter.
##-------------------------------------------------------

CLOBBER=${xCLOBBER-$CLOBBER}
if [ ! "$CLOBBER" = "true" ] ; then
       CLOBBER="false"
fi

##-------------------------------------------------------
## For each pathname variable:
## Make sure it's defined.
## Strip trailing slashes from each of the directory variables.
## Determine length of longest parameter name.
##-------------------------------------------------------

len=0
for i in $paths; do

# Is it defined?
        eval "test \"\$${i}\""
        if [ $? -ne 0 ] ; then
                echo "Error: configuration parameter \$$i undefined." 1>&2
                echo "There is an error in the configuration file ${INSTALL_CONFIG_FILE}." 1>&2
                exit 1
        fi

# Strip trailing slashes.
# Squash multiple internal slashes down to one.
        eval "xtmp=\$${i}"
        xtmp=`echo $xtmp | sed 's/\/*$//'`
        xtmp=`echo $xtmp | sed 's/\/\/*/\//g'`
        eval "${i}=\"$xtmp\""

# Does it start with a slash (i.e. is it an absolute pathname)?
        ytmp=`echo $xtmp | sed 's/^\///'`
        if [ "$xtmp" = "$ytmp" ] ; then
                echo "Error: \$$i is not an absolute pathname." 1>&2
                echo 'Relative pathnames may not be used.' 1>&2
                exit 1
        fi

# What is the length of the longest variable name?
        if [ "$AWK" != "" ] ; then
                xlen=`echo "${i}" | $AWK '{ print length }'`
                if [ $xlen -gt $len ] ; then
                        len=$xlen
                fi
        fi
done

##-------------------------------------------------------
## Check Mailmethod for SMTP.  If SMTP ignore MAILPROGRAM.
## If SENDMAIL is specified, verify that the specified
## mail program exists
##-------------------------------------------------------
echo "Checking for programs specified in install variables...."
echo

TWMAILMETHOD=${TWMAILMETHOD:-'SENDMAIL'}
if [ "$TWMAILMETHOD" = "SENDMAIL" ] ; then

        TWMAILPROGRAM=${TWMAILPROGRAM:-'/usr/lib/sendmail -oi -t'}
        TWMAILTEST=`echo ${TWMAILPROGRAM} | sed -e 's/ .*//'`

        if [ -x ${TWMAILTEST} ] ; then
                echo "${TWMAILTEST} exists.  Continuing installation."
                echo
        else
                echo "$TWMAILPROGRAM does not exist.  Exiting."
                exit 1
        fi
else
        echo "Using SMTP mail protocol."
        echo "MAILPROGRAM variable will be ignored."
        echo "Continuing installation."
        echo
        fi

##-------------------------------------------------------
## Verify that the specified editor program exists
##-------------------------------------------------------

TWEDITOR=${TWEDITOR:-'/bin/vi'}

if [ -x ${TWEDITOR} ]; then
        echo "${TWEDITOR} exists.  Continuing installation."
        echo
else
        echo "${TWEDITOR} does not exist.  Exiting."
        exit 1
fi

##-------------------------------------------------------
## Print the list of target directories.
##-------------------------------------------------------

echo "This program will copy Tripwire files to the following directories:"
echo

for i in $paths; do
        if [ "$AWK" != "" ] ; then
                eval "echo \"${i}\"     | $AWK '{printf \"%${len}s: \", \$1}'"
                eval "echo \"\$${i}\""
        else
                eval "echo \"\$${i}\""
        fi
done

##-------------------------------------------------------
## Display value of clobber.
##-------------------------------------------------------

echo
echo "CLOBBER is $CLOBBER."

##-------------------------------------------------------
## Prompt to continue.
##-------------------------------------------------------

if [ "$PROMPT" = "true" ] ; then
        echo
        (echo $n "Continue with installation? [y/n] " $c) 1>&2
        read ans
        case "$ans" in
                [yY]*) ;;
                *) echo "Installation has been halted."
                        exit 1;
                        ;;
        esac
fi

##=======================================================
## Create directories.
##=======================================================

echo
echo "----------------------------------------------"
echo "Creating directories..."

##-------------------------------------------------------
## Create only directories that do not already exist.
## Change permissions only on directories we create.
## Exit if mkdir fails.
##-------------------------------------------------------

for i in $path2; do
        eval "d=\$${i}"
        if [ ! -d "$d" ] ; then
                mkdir -p "$d"
                if [ ! -d "$d" ] ; then
                        echo "Error: unable to create directory $d"
                        exit 1
                else
                        echo "$d: created"
                        chmod 0755 "$d" > /dev/null
                fi
        else
                echo "$d: already exists"
        fi
done

for i in $path3; do
        eval "d=\$${i}"
        if [ ! -d "$d" ] ; then
                mkdir -p "$d"
                if [ ! -d "$d" ] ; then
                        echo "Error: unable to create directory $d"
                        exit 1
                else
                        echo "$d: created"
                        chmod 0755 "$d" > /dev/null
                fi
        else
                echo "$d: already exists"
        fi
done


##=======================================================
## Copy all files to correct locations.
##=======================================================

echo
echo "----------------------------------------------"
echo "Copying files..."

##-------------------------------------------------------
## Did the binaries build okay?  If so, copy them to the
## correct location
##-------------------------------------------------------

binaries="$TRIPWIRE $TWADMIN $TWPRINT $SIGGEN"

for i in $binaries; do
if [ -s "$BIN_DIR_NAME/$i" ] ; then
    echo "$i binary built successfully"
    cp "$BIN_DIR_NAME/$i" "$TWBIN"
    if [ $? -eq 0 ]; then
        echo "$i: copied"
        chmod 0755 "$TWBIN/$i" > /dev/null
        else
        echo "$i: copy failed"
    fi
else
    echo "$i did not build successfully.  See RPM output for details."
    echo "RPM build failed."
    exit 1
fi
done

##-------------------------------------------------------
## Copy all other files
##-------------------------------------------------------

# Copy Readme, Release Notes, License

fil="$README $REL_NOTES $TWLICENSEFILE policyguide.txt TRADEMARK"

echo "twdocs="$TWDOCS
for i in $fil; do
    cp "$BASE_DIR_NAME/$i" "$TWDOCS"
    if [ $? -eq 0 ]; then
        echo "$i: copied"
        chmod 0644 "$TWDOCS/$i" > /dev/null
    else
        echo "$i: copy failed"
    fi
done

# Copy man pages
man8="man8/tripwire.8 man8/twadmin.8 man8/twprint.8 man8/siggen.8 man8/twintro.8"
man5="man5/twfiles.5"
man4="man4/twpolicy.4 man4/twconfig.4"
for i in $man8 $man5 $man4; do
cp "$CD_MANUAL_NAME/$i" "$TWMAN/$i"
    if [ $? -eq 0 ]; then
        echo "$i: copied"
        chmod 0444 "$TWMAN/$i" > /dev/null
    else
        echo "$i: copy failed"
    fi
done

# Copy policy files
polfiles="$CLR_POLICY_FILE twinstall.sh.bak"
for i in $polfiles; do
cp "$CD_EXTRA_NAME/$i" "$TWPOLICY"
    if [ $? -eq 0 ]; then
        echo "$i: copied"
    else
        echo "$i: copy failed"
    fi
done

##=======================================================
## Files are now present on user's system.
## Tripwire configuration for binary RPM install.
##=======================================================

#######################################################################
# Binary RPM Installer
#######################################################################

%post

# Twadmin binary
TWADMIN="twadmin"

# Path to twadmin executeable
TWADMPATH="/usr/sbin"

# License File name
TWLICENSEFILE="COPYING"

# Default Tripwire configuration file.
TW_CONFIG_FILE="tw.cfg"

# Path to configuration directory
CONF_PATH="/etc/tripwire"

# Name of initial cleartext Tripwire configuration file.
CLR_CONFIG_FILE="twcfg.txt"

# Name of initial cleartext Tripwire policy file.
CLR_POLICY_FILE="twpol.txt"

# Name of the Readme file.
README="README"

# Starting directory.
START_DIR=`pwd`

# Site passphrase.
TW_SITE_PASS=""

# Local passphrase.
TW_LOCAL_PASS=""

# If CLOBBER is false, existing files are not overwritten.
CLOBBER=false

# If prompt==true, ask for confirmation before continuing with install.
PROMPT="true"

# Tripwire installation documents are stored in TWDOCS.
TWDOCS="/usr/doc/tripwire"

# Tripwire binaries are stored in TWBIN.
TWBIN="/usr/sbin"

# Tripwire configuration files are stored in TWCFG.
TWCFG="/etc/tripwire"

# Tripwire policy files are stored in TWPOLICY.
TWPOLICY="${TWCFG}"

# Tripwire manual pages are stored in TWMAN.
TWMAN="/usr/man"

# Tripwire database files are stored in TWDB.
TWDB="/var/lib/tripwire"

# The Tripwire site key files are stored in TWSITEKEYDIR.
TWSITEKEYDIR="${TWCFG}"

# The Tripwire local key files are stored in TWLOCALKEYDIR.
TWLOCALKEYDIR="${TWCFG}"

# Tripwire report files are stored in TWREPORT.
TWREPORT="/var/lib/tripwire/report"

# This sets the default text editor for Tripwire.
TWEDITOR="/bin/vi"

# TWLATEPROMTING controls the point when tripwire asks for a password.
TWLATEPROMPTING=false

# TWLOOSEDIRCHK selects whether the directory should be monitored for
# properties that change when files in the directory are monitored.
TWLOOSEDIRCHK=false

# TWMAILNOVIOLATIONS determines whether Tripwire sends a no violation
# report when integrity check is run with --email-report but no rule
# violations are found.  This lets the admin know that the integrity
# was run, as opposed to having failed for some reason.
TWMAILNOVIOLATIONS=true

# TWEMAILREPORTLEVEL determines the verbosity of e-mail reports.
TWEMAILREPORTLEVEL=3

# TWREPORTLEVEL determines the verbosity of report printouts.
TWREPORTLEVEL=3

# TWSYSLOG determines whether Tripwire will log events to the system log
TWSYSLOG=false

#####################################
# Mail Options - Choose the appropriate
# method and comment the other section
#####################################

#####################################
# SENDMAIL options - DEFAULT
#
# Either SENDMAIL or SMTP can be used to send reports via TWMAILMETHOD.
# Specifies which sendmail program to use.
#####################################

TWMAILMETHOD=SENDMAIL
TWMAILPROGRAM="/usr/lib/sendmail -oi -t"

#####################################
# SMTP options
#
# TWSMTPHOST selects the SMTP host to be used to send reports.
# SMTPPORT selects the SMTP port for the SMTP mail program to use.
#####################################

# TWMAILMETHOD=SMTP
# TWSMTPHOST="mail.domain.com"
# TWSMTPPORT=25

##-------------------------------------------------------
## Set default values for Tripwire file names.
##-------------------------------------------------------

HOST_NAME='localhost'
(uname -n) 2> /dev/null 1>&2
if [ $? -eq 0 ]; then
    HOST_NAME=`uname -n`
fi

LOCAL_KEY="${TWLOCALKEYDIR}/${HOST_NAME}-local.key"
SITE_KEY="${TWSITEKEYDIR}/site.key"
CONFIG_FILE="${TWBIN}/$TW_CONFIG_FILE"  # Signed config file
POLICY_FILE="${TWPOLICY}/tw.pol"        # Signed policy file
TXT_CFG="$TWCFG/${CLR_CONFIG_FILE}"   # Cleartext config file
TXT_POL="${TWPOLICY}/$CLR_POLICY_FILE"  # Cleartext policy file

TWADMIN="${TWBIN}/twadmin"

##=======================================================
## Generate tripwire configuration file.
##=======================================================

echo
echo "----------------------------------------------"
echo "Generating Tripwire configuration file..."

cat << END_OF_TEXT > "$TXT_CFG"
ROOT          =$TWBIN
POLFILE       =$POLICY_FILE
DBFILE        =$TWDB/\$(HOSTNAME).twd
REPORTFILE    =$TWREPORT/\$(HOSTNAME)-\$(DATE).twr
SITEKEYFILE   =$SITE_KEY
LOCALKEYFILE  =$LOCAL_KEY
EDITOR        =$TWEDITOR
LATEPROMPTING =${TWLATEPROMPTING:-false}
LOOSEDIRECTORYCHECKING =${TWLOOSEDIRCHK:-false}
MAILNOVIOLATIONS =${TWMAILNOVIOLATIONS:-true}
EMAILREPORTLEVEL =${TWEMAILREPORTLEVEL:-3}
REPORTLEVEL   =${TWREPORTLEVEL:-3}
MAILMETHOD    =${TWMAILMETHOD:-SENDMAIL}
SYSLOGREPORTING =${TWSYSLOG:=true}
END_OF_TEXT

if [ "$TWMAILMETHOD" = "SMTP" ] ; then
cat << SMTP_TEXT >> "$TXT_CFG"
SMTPHOST      =${TWSMTPHOST:-mail.domain.com}
SMTPPORT      =${TWSMTPPORT:-"25"}
SMTP_TEXT
else
cat << SENDMAIL_TEXT >> "$TXT_CFG"
MAILPROGRAM   =$TWMAILPROGRAM
SENDMAIL_TEXT
fi

if [ ! -s "$TXT_CFG" ] ; then
        echo "Error: unable to create $TXT_CFG"
        exit 1
fi

chmod 0644 "$TXT_CFG"

##=======================================================
## Modify default policy file with file locations
##=======================================================

echo
echo "----------------------------------------------"
echo "Customizing default policy file..."

sed '/@@section GLOBAL/,/@@section FS/  {
  s?^\(TWROOT=\).*$?\1'\""$TWBIN"\"';?
  s?^\(TWBIN=\).*$?\1'\""$TWBIN"\"';?
  s?^\(TWPOL=\).*$?\1'\""$TWPOLICY"\"';?
  s?^\(TWDB=\).*$?\1'\""$TWDB"\"';?
  s?^\(TWSKEY=\).*$?\1'\""$TWSITEKEYDIR"\"';?
  s?^\(TWLKEY=\).*$?\1'\""$TWLOCALKEYDIR"\"';?
  s?^\(TWREPORT=\).*$?\1'\""$TWREPORT"\"';?
  s?^\(HOSTNAME=\).*$?\1'"$HOST_NAME"';?
}' "${TXT_POL}" > "${TXT_POL}.tmp"

# copy the tmp file back over the default policy
cp "${TXT_POL}" "${TXT_POL}.bak"
mv "${TXT_POL}.tmp" "${TXT_POL}"

# reset rights on the policy files to 644
chmod 0644 "$TXT_POL"
chmod 0644 "${TXT_POL}.bak"

cat << END_OF_TEXT

A clear-text version of the Tripwire policy file
$TXT_POL
has been created for your inspection.  This implements
a minimal policy, intended only to test essential
Tripwire functionality.  You should edit the policy file
to describe your system, and then use twadmin to generate
a signed copy of the Tripwire policy.

END_OF_TEXT

##=======================================================
## Edit twinstall.sh to include correct path values
##=======================================================

sed -e "{
    s^_SITEKEYPATH_^$TWSITEKEYDIR^
    s^_LOCALKEYPATH_^$TWLOCALKEYDIR^
    s^_ADMVAR_^$TWBIN^
    s^_CONFPATH_^$TWCFG^
    }" $TWCFG/twinstall.sh.bak > $TWCFG/twinstall.sh

chmod 750 $TWCFG/twinstall.sh

#########################################################
## If passphrase variables were set, create keyfiles and
## encrypt config/policy files.  Otherwise just finish
## install.  The following mimics contents of twinstall.sh
## post-install script.
#########################################################

if [ -n "$TW_SITE_PASS" ] || [ -n "$TW_LOCAL_PASS" ]; then

    ##=======================================================
    ## Create Key Files
    ##=======================================================

    ##-------------------------------------------------------
    ## If user has to enter a passphrase, give some
    ## advice about what is appropriate.
    ##-------------------------------------------------------

if [ -z "$TW_SITE_PASS" ] || [ -z "$TW_LOCAL_PASS" ]; then
cat << END_OF_TEXT

----------------------------------------------
The Tripwire site and local passphrases are used to
sign a variety of files, such as the configuration,
policy, and database files.

Passphrases should be at least 8 characters in length
and contain both letters and numbers.

See the Tripwire manual for more information.
END_OF_TEXT
fi

    ##=======================================================
    ## Generate keys.
    ##=======================================================

    echo
    echo "----------------------------------------------"
    echo "Creating key files..."

    ##-------------------------------------------------------
    ## Site key file.
    ##-------------------------------------------------------

    # If clobber is true, and prompting is off (unattended operation)
    # and the key file already exists, remove it.  Otherwise twadmin
    # will prompt with an "are you sure?" message.

    if [ "$CLOBBER" = "true" ] && [ "$PROMPT" = "false" ] && [ -f "$SITE_KEY" ] ; then
        rm -f "$SITE_KEY"
    fi

    if [ -f "$SITE_KEY" ] && [ "$CLOBBER" = "false" ] ; then
	echo "The site key file \"$SITE_KEY\""
	echo 'exists and will not be overwritten.'
    else
	cmdargs="--generate-keys --site-keyfile \"$SITE_KEY\""
	if [ -n "$TW_SITE_PASS" ] ; then
		cmdargs="$cmdargs --site-passphrase \"$TW_SITE_PASS\""
     	fi
	eval "\"$TWADMPATH/$TWADMIN\" $cmdargs"
	if [ $? -ne 0 ] ; then
		echo "Error: site key generation failed"
		exit 1
        else chmod 644 "$SITE_KEY"
	fi
    fi

    ##-------------------------------------------------------
    ## Local key file.
    ##-------------------------------------------------------

    # If clobber is true, and prompting is off (unattended operation)
    # and the key file already exists, remove it.  Otherwise twadmin
    # will prompt with an "are you sure?" message.

    if [ "$CLOBBER" = "true" ] && [ "$PROMPT" = "false" ] && [ -f "$LOCAL_KEY" ] ; then
        rm -f "$LOCAL_KEY"
    fi

    if [ -f "$LOCAL_KEY" ] && [ "$CLOBBER" = "false" ] ; then
	echo "The site key file \"$LOCAL_KEY\""
	echo 'exists and will not be overwritten.'
    else
	cmdargs="--generate-keys --local-keyfile \"$LOCAL_KEY\""
	if [ -n "$TW_LOCAL_PASS" ] ; then
		cmdargs="$cmdargs --local-passphrase \"$TW_LOCAL_PASS\""
        fi
	eval "\"$TWADMPATH/$TWADMIN\" $cmdargs"
	if [ $? -ne 0 ] ; then
		echo "Error: local key generation failed"
		exit 1
        else chmod 644 "$LOCAL_KEY"
	fi
    fi

    ##=======================================================
    ## Sign the Configuration File
    ##=======================================================

    echo
    echo "----------------------------------------------"
    echo "Signing configuration file..."

    ##-------------------------------------------------------
    ## If noclobber, then backup any existing config file.
    ##-------------------------------------------------------

    if [ "$CLOBBER" = "false" ] && [ -s "$CONFIG_FILE" ] ; then
	backup="${CONFIG_FILE}.$$.bak"
	echo "Backing up $CONFIG_FILE"
	echo "        to $backup"
	`mv "$CONF_PATH/$CONFIG_FILE" "$CONF_PATH/$backup"`
	if [ $? -ne 0 ] ; then
		echo "Error: backup of configuration file failed."
		exit 1
	fi
    fi

    ##-------------------------------------------------------
    ## Build command line.
    ##-------------------------------------------------------

    cmdargs="--create-cfgfile"
    cmdargs="$cmdargs --cfgfile \"$CONFIG_FILE\""
    cmdargs="$cmdargs --site-keyfile \"$SITE_KEY\""
    if [ -n "$TW_SITE_PASS" ] ; then
	cmdargs="$cmdargs --site-passphrase \"$TW_SITE_PASS\""
    fi

    ##-------------------------------------------------------
    ## Sign the file.
    ##-------------------------------------------------------

    eval "\"$TWADMPATH/$TWADMIN\" $cmdargs \"$TXT_CFG\""
    if [ $? -ne 0 ] ; then
	echo "Error: signing of configuration file failed."
	exit 1
    fi

    # Set the rights properly
    chmod 644 "/CONF_PATH/$CONFIG_FILE"

    ##-------------------------------------------------------
    ## We keep the cleartext version around.
    ##-------------------------------------------------------

cat << END_OF_TEXT

clear-text version of the Tripwire configuration file
$CONF_PATH/$TXT_CFG
has been preserved for your inspection.  It is recommended
that you delete this file manually after you have examined it.

END_OF_TEXT

    ##=======================================================
    ## Sign tripwire policy file.
    ##=======================================================

    echo
    echo "----------------------------------------------"
    echo "Signing policy file..."

    ##-------------------------------------------------------
    ## If noclobber, then backup any existing policy file.
    ##-------------------------------------------------------

    if [ "$CLOBBER" = "false" ] && [ -s "$POLICY_FILE" ] ; then
	backup="${POLICY_FILE}.$$.bak"
	echo "Backing up $POLICY_FILE"
	echo "        to $backup"
	mv "$POLICY_FILE" "$backup"
	if [ $? -ne 0 ] ; then
		echo "Error: backup of policy file failed."
		exit 1
	fi
    fi

    ##-------------------------------------------------------
    ## Build command line.
    ##-------------------------------------------------------

    cmdargs="--create-polfile"
    cmdargs="$cmdargs --cfgfile \"$CONFIG_FILE\""
    cmdargs="$cmdargs --site-keyfile \"$SITE_KEY\""
    if [ -n "$TW_SITE_PASS" ] ; then
	cmdargs="$cmdargs --site-passphrase \"$TW_SITE_PASS\""
    fi

    ##-------------------------------------------------------
    ## Sign the file.
    ##-------------------------------------------------------

    eval "\"$TWADMPATH/$TWADMIN\" $cmdargs \"$TXT_POL\""
    if [ $? -ne 0 ] ; then
	echo "Error: signing of policy file failed."
	exit 1
    fi

    # Set the proper rights on the newly signed policy file.
    chmod 0644 "$POLICY_FILE"

    ##-------------------------------------------------------
    ## We keep the cleartext version around.
    ##-------------------------------------------------------

cat << END_OF_TEXT

A clear-text version of the Tripwire policy file
$TXT_POL
has been preserved for your inspection.  This implements
a minimal policy, intended only to test essential
Tripwire functionality.  You should edit the policy file
to describe your system, and then use twadmin to generate
a new signed copy of the Tripwire policy.

END_OF_TEXT


    else
        echo "IMPORTANT:  To complete the Tripwire 2.3 installation,"
        echo "you must run the configuration script: "
        echo "$TWCFG/twinstall.sh"
        echo
        echo "This script walks you through the processes of "
        echo "setting passphrases and encrypting the policy"
        echo "and configuration files.  If you wish to change the"
        echo "contents of your policy file, $TXT_POL"
	echo "you may want to do so before running this script."
fi

##=======================================================
## Closing:  give location of Readme
##=======================================================

cat << END_OF_TEXT

----------------------------------------------
The installation succeeded.

Please refer to $TWDOCS/$README
for release information and to the printed user documentation for
further instructions on using Open Source Tripwire 2.3 for Linux.

END_OF_TEXT

cd "$START_DIR"

%verifyscript

TWDIR="/usr/sbin"
files="$TWDIR/siggen $TWDIR/tripwire $TWDIR/twprint $TWDIR/twadmin"
for i in files; do
    if [ -s "$i" ] ; then
        echo "$i found"
    else
        echo "$i missing.  Install did not complete successfully.
        exit 1
    fi
done

#######################################################################
# Files to be packaged
#######################################################################

%files
/etc/tripwire/twinstall.sh.bak
/etc/tripwire/twpol.txt
/usr/sbin/tripwire
/usr/sbin/twadmin
/usr/sbin/twprint
/usr/sbin/siggen


%dir
/var/lib/tripwire/report


%doc
/usr/doc/tripwire/TRADEMARK
/usr/doc/tripwire/README
/usr/doc/tripwire/Release_Notes
/usr/doc/tripwire/COPYING
/usr/doc/tripwire/policyguide.txt
/usr/man/man4/twpolicy.4
/usr/man/man4/twconfig.4
/usr/man/man5/twfiles.5
/usr/man/man8/siggen.8
/usr/man/man8/tripwire.8
/usr/man/man8/twadmin.8
/usr/man/man8/twintro.8
/usr/man/man8/twprint.8

#######################################################################
# Remove all installed source RPM files
#######################################################################

%clean
rm $RPM_SOURCE_DIR/tripwire.*
rm -R $RPM_BUILD_DIR/*
rm -R /usr/doc/tripwire/*
rm -R /var/lib/tripwire/*
rm -R /etc/tripwire/*
rmdir /usr/doc/tripwire
rmdir /var/lib/tripwire
rmdir /etc/tripwire
rm /usr/man/man4/twpolicy.4
rm /usr/man/man4/twconfig.4
rm /usr/man/man5/twfiles.5
rm /usr/man/man8/siggen.8
rm /usr/man/man8/tripwire.8
rm /usr/man/man8/twadmin.8
rm /usr/man/man8/twintro.8
rm /usr/man/man8/twprint.8
rm /usr/sbin/tripwire
rm /usr/sbin/twadmin
rm /usr/sbin/twprint
rm /usr/sbin/siggen

#######################################################################
# Binary RPM removal instructions
#######################################################################

%postun
# Delete Tripwire files in bulk where possible, manually where you have to.
rm -R /etc/tripwire/*

# Delete extra Tripwire directories
rmdir /etc/tripwire

########################################################################
########################################################################
#
#                        TRIPWIRE GPL NOTICES
#
# The developer of the original code and/or files is Tripwire, Inc.
# Portions created by Tripwire, Inc. are Copyright © 2000 Tripwire, Inc.
# Tripwire is a registered trademark of Tripwire, Inc.  All rights reserved.
#
# This program is free software.  The contents of this file are subject to
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.  You may redistribute it and/or modify it only in
# compliance with the GNU General Public License.
#
# This program is distributed in the hope that it will be useful.  However,
# this program is distributed "AS-IS" WITHOUT ANY WARRANTY; INCLUDING THE
# IMPLIED WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
# Please see the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Nothing in the GNU General Public License or any other license to use the
# code or files shall permit you to use Tripwire's trademarks,
# service marks, or other intellectual property without Tripwire's
# prior written consent.
#
# If you have any questions, please contact Tripwire, Inc. at either
# info@tripwire.org or www.tripwire.org.
#
########################################################################
########################################################################
