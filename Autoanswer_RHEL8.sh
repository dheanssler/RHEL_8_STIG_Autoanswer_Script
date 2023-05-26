#/bin/bash
#Check if script is being run as root.
if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  printf "Script executed as root...\n"
else
  IAMROOT="0"
  printf "WARNING: This script has not been executed with root privileges.\nExiting...\n"
  exit
fi

#Change directory to script directory.
parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"

#Ensure Path Variable Contains sbin
PATH=$PATH:/usr/sbin

#Get List of Local Users
localUsers=$(cat /etc/passwd | grep -Ev "nologin|false|sync|shutdown|true|halt" | awk -F ':' '{print $1}')
allLocalUsers=$(cat /etc/passwd | awk -F ':' '{print $1}')

#Get Red Hat Release Version
release=$(grep -E -o "8\.[0-9]+" /etc/redhat-release)


#########FUNCTIONS##########
printResults () {
	questionNumber=$1
	result=$2
	reason=$3

	case $result in
		"FIND")
			printf "Question Number $questionNumber: Finding\n"
			printf "\tReason: $reason\n"
			;;
		"NFIND")
			printf "Question Number $questionNumber: Not a Finding.\n"
			;;
		"PFIND")
			printf "Question Number $questionNumber: Potential Finding: $reason\n"
			;;
		"REVIEW")
			printf "Question Number $questionNumber: $reason\n"
			;;
		"ADD")
			printf "\t$reason\n"
			;;
		"NOTAPPLICABLE")
			printf "Question Number $questionNumber: Not applicable.\n"
			;;
		*)
			printf "ERROR"
			;;
	esac
}


checkForSetting () {
	oldIFS=$IFS
	IFS=$'\n'
	searchString=$1
	searchLocation=$2
	questionNumber=$3

	#echo $searchString
	#echo $searchLocation
	#echo $questionNumber

	searchResults=$(sudo grep -rioh $searchString $searchLocation 2>/dev/null)
	IFS=$oldIFS
	#echo $searchResults

	if [ "${searchResults^^}" == "${searchString^^}" ]; then
		printResults "$questionNumber" "NFIND" ""
	else
		printResults "$questionNumber" "FIND" "The setting '$searchString' was not found in the configuration file '$searchLocation'."
	fi
}

checkUnitFile () {
	unitFileName=$1
	expectedStatus=$2
	expectedReturnCode=$3
	questionNumber=$4
	unitFileCheck=$(systemctl is-enabled $1 2>/dev/null)
	checkReturnCode=$?
	expectedActive=$5
	isActive=$(systemctl is-active $1 2>/dev/null)
	
	if [ "$unitFileCheck " == "$expectedStatus " ] && [ $checkReturnCode -eq $expectedReturnCode ] && [ $isActive == $expectedActive ]; then
		printResults "$questionNumber" "NFIND" ""
	else
		printResults "$questionNumber" "FIND" "The unit file '$unitFileName' is $unitFileCheck and $isActive.\n"
	fi
}

checkUpdateHistory () {
	questionNumber=$1
	dnfHistory=$(dnf history list | head -n 8 )
	printResults "$questionNumber" "REVIEW" "Review the following update history and confirm that updates are being performed in accordance with program requirements.\n$dnfHistory\n"
}

checkDriveEncryption () {
	questionNumber=$1
	allBlockDevices=$(blkid | awk '{print substr($1,1,length($1)-1)}')
	nonLuksBlockDevices=$(blkid | grep -v "crypto_LUKS" | awk '{print substr($1,1,length($1)-1)}')
	luksBlockDevices=$(blkid | grep "crypto_LUKS" | awk '{print substr($1,1,length($1)-1)}')
	printf "Question Number $questionNumber: Review the following block devices. Ask the system administrator about any devices indicated as not being encrypted. If there is no evidence that a partition or block device is encrypted, this is a finding. \n"
	if [ -x "$(command -v cryptsetup)" ]; then
		for blockDevice in $luksBlockDevices; do
			luksDumpResults=$(sudo cryptsetup luksDump $blockDevice)
			luksCipher=$(echo -n "$luksDumpResults" | grep "Cipher:")
			luksKeyLength=$(echo "$luksDumpResults" | grep -E -o "Cipher key:\s[0-9]+" | grep -E -o "[0-9]+")
			if [[ $luksCipher =~ "aes" ]]; then
				if [ "$luksKeyLength" -gt "511" ]; then
					printResults "" "ADD" "Not a Finding: $blockDevice is encrypted with AES-256 bit encryption."
				else
					printResults "" "ADD" "Potential Finding: $blockDevice effective encryption key size is less than 256 bits."
				fi
			else
				printResults "" "ADD" "Potential Finding: $blockDevice is not encrypted using an AES algorithm."
			fi
		done
	else
		printResults "" "ADD" "Potential Finding: CRYPTSETUP COMMAND NOT FOUND"
	fi
	
	for blockDevice in $nonLuksBlockDevices; do
		printResults "" "ADD" "Potential Finding: $blockDevice is not encrypted."
	done
}

checkForBanner () {
	searchTerm=$1
	searchLocation=$2
	expectedBannerLength=$3
	questionNumber=$4
	bannerLocation=$(grep -vrh "#" "$searchLocation" | grep -i "$searchTerm" | grep -E -o "/.*")
	if (( "$(echo -n $bannerLocation | wc -c)" > 0 )); then
		bannerWordCount=$(cat $bannerLocation | wc -w)
		if [ $bannerWordCount -eq "$expectedBannerLength" ]; then
			printResults "$questionNumber" "NFIND" ""
		else
			printResults "$questionNumber" "FIND" "The word count ($bannerWordCount) of the file does not match the word count of the standard DOD Notice and Consent Banner."
		fi
	else
		printResults "$questionNumber" "FIND" "The path to $searchTerm was not set in the configuration file $searchLocation."
	fi
}

checkSettingContains () {
	searchString=$1
	searchLocation=$2
	matchString=$3
	questionNumber=$4

	searchResults=$(sudo grep -ih $searchString $searchLocation 2>/dev/null)

	if [[ "${searchResults^^}" =~ "${matchString^^}" ]]; then
		printResults "$questionNumber" "NFIND" ""
	else
		printResults "$questionNumber" "FIND" "The setting '$matchString' was not found in the configuration file '$searchLocation'."
	fi
}

needtoRevist () {
	questionNumber=$1
	printResults "$questionNumber" "FIND" "The requirements for meeting this STIG aren't clear or the path forward isn't immediately clear."
}

checkDODRootCA () {
	questionNumber=$1
	searchResults=$(sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem 2>/dev/null)
	if (( "$(echo -n $searchResults | wc -c)" > 0 )); then
		printResults "$questionNumber" "REVIEW" "Review the following certificate information to confirm that the root ca is a DoD-issued certificate with a valid date."
	else
		printResults "$questionNumber" "PFIND" "If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable."
	fi
}

checkSSHKeyPasswords () {
	printf "Question Number 11: Review the following files identified as potential private keys. If there are any private keys that are not password protected, this is a finding. \n"
	sshDirectories=$(find / -type d -name .ssh 2>/dev/null)
	for sshDirectory in $sshDirectories; do
		for file in $(ls $sshDirectory | grep -v .pub); do
			result=$(ssh-keygen -y -P "" -f "$sshDirectory/$file" 2>&1)
			if [[ $result =~ "incorrect passphrase" ]]; then
				printResults "" "ADD" "Not a Finding: $sshDirectory/$file is password protected"
			elif [[ $result =~ "invalid format" ]]; then
				echo -n ""
			elif [[ $result =~ "ssh-" ]]; then
				printResults "" "ADD" "Finding: $sshDirectory/$file is not password protected."
			elif [[ $result =~ "UNPROTECTED PRIVATE KEY FILE" ]]; then
				printResults "" "ADD" "Finding: $sshDirectory/$file has incorrect file permissions"
			else
				printResults "" "ADD" "Potential Finding: Output not recognized for $sshDirectory/$file. Verify manually."
			fi
		done
	done
}

#"key" "command" "expected result" "questionNumber" "secondKey" "secondCommand" "secondMatchString"
checkCommandOutput () {
	key=$1
	command=$2
	matchString=$3
	questionNumber=$4
	key2=$5
	command2=$6
	matchString2=$7
	result=$($command 2>&1 | grep -E $key)
	
	if [[ $result =~ "$matchString" ]]; then
		printResults "$questionNumber" "NFIND" ""
	else
		if [[ $key2 ]]; then
			result=$($command2 2>&1 | grep -E $key2)
			if [[ $result =~ "$matchString2" ]]; then
				printResults "$questionNumber" "NFIND" ""
			else
				printResults "$questionNumber" "PFIND" "The output of '$command' did not return the expected result '$key$matchString'\n\tThe result was '$result'"
			fi
		else
			printResults "$questionNumber" "PFIND" "The output of '$command' did not return the expected result '$key$matchString'\n\tThe result found was '$result'"
		fi
		
	fi
}

checkCommandOutputImproved () {
		questionNumber=$1
		command=$2
		expectedOutput=$3
		reason=$4
		result=$($command 2>&1)
		if [[ $result =~ $expectedOutput ]]; then
			printResults "$questionNumber" "NFIND" ""
		else
			printResults "$questionNumber" "PFIND" "The output of '$command' did not return the expected result '$expectedOutput'. The result was '$result'. $reason"
		fi		
}

# "startDirectory" "type" "permissions" "failIfFound" "questionNumber" "" "followSymLinks"
checkFilePermissions () {
	startDirectory=$1
	type=$2
	permissions=$3
	permissions2=$(echo -n $3 | tr -d '"')
	failIfFound=$4
	questionNumber=$5
	followSymLinks=$7
	secondaryFilter=$8
	results=""
	
	if [ $followSymLinks == "TRUE" ]; then
		result=$(find -L $startDirectory -type $type $permissions2 -print 2>/dev/null)
		
	else
		result=$(find $startDirectory -type $type $permissions2 -print 2>/dev/null)
	fi
	
	if [[ -n $secondaryFilter ]]; then
		result=$(echo "$result" | grep -v -E $secondaryFilter)
	fi
	
	if [[ $result ]]; then
		if [ $failIfFound == "TRUE" ]; then
			printResults "$questionNumber" "FIND" "One or more objects of type '$type' within directory '$startDirectory' were identified that $6\nMatching Objects:\n$result"
		else
			printResults "$questionNumber" "NFIND" ""
		fi
	else #not found
		if [ $failIfFound == "TRUE" ]; then
			printResults "$questionNumber" "NFIND" ""
		else
			printResults "$questionNumber" "FIND" "No objects of type '$type' within directory '$startDirectory' were identified that $6"
		fi
	fi
}

checkCronjob () {
	name=$1
	questionNumber=$2
	cronJobs=$(crontab -l | grep -v "#" | grep -i "$name")
	if [ -x "$(command -v $name)" ]; then
		printf "Question Number $questionNumber: Review the following and validate that the cronjobs are configured per organization standards\n"
		if [[ $cronJobs ]]; then
			printResults "" "ADD" "Cronjobs identified via crontab -l for the root user:\n\t$cronJobs"
		else
			cronJobs=$(grep -rH $name /etc/cron.*)
			if [[ $cronJobs ]]; then
				printResults "" "ADD" "Cronjobs identified via via /etc/cron.* files:\n\t$cronJobs"
			else
				printResults "" "ADD" "Finding: No cronjob for $name was found" 
			fi
		fi
	else
		printResults "$questionNumber" "FIND" "Finding: The binary $name does not appear to be installed or available in the current PATH variable"
	fi
	
}

checkFileSystemTable () {
	questionNumber=$1
	searchTerm=$2
	failIfFound=$3
	reason2=$4
	oldIFS=$IFS
	IFS=$'\n'
	results=$(grep -v "#" /etc/fstab)
	printf "Question Number $questionNumber: Review the following file system mounts:\n"
	if [ $failIfFound == "TRUE" ]; then
		for result in $results; do
			mountPoint=$(echo -n $result | awk '{print $2}')
			fileSystemType=$(echo -n $result | awk '{print $3}')
			if [[ $result =~ $searchTerm ]]; then
				printResults "" "ADD" "Potential Finding: The option $searchTerm was found for mount '$mountPoint' of type '$fileSystemType'. $reason2"
			else
				printResults "" "ADD" "Not a Finding: The option $searchTerm was not found for mount '$mountPoint' of type '$fileSystemType'."
			fi
		done
	else
		for result in $results; do
			mountPoint=$(echo -n $result | awk '{print $2}')
			fileSystemType=$(echo -n $result | awk '{print $3}')
			if [[ ! $result =~ $searchTerm ]]; then
				printResults "" "ADD" "Potential Finding: The option $searchTerm was not found for mount '$mountPoint' of type '$fileSystemType'. $reason2"
			else
				printResults "" "ADD" "Not a Finding: The option $searchTerm was found for mount '$mountPoint' of type '$fileSystemType'."
			fi
		done
	fi
	
	
	IFS=$oldIFS

}

#checkFileSystemTableSpecific "94" "nosuid" "FALSE" "/boot/efi" "Confirm that this mounted file system does not refer to removable media."
checkFileSystemTableSpecific () {
	questionNumber=$1
	searchTerm=$2
	failIfFound=$3
	mountPoint=$4
	reason=$5

	results=$(grep -v "#" /etc/fstab | grep $mountPoint)
	printResults "$questionNumber" "REVIEW" "Review the following file system mounts:"
	if [ $failIfFound == "TRUE" ]; then
		for result in $results; do
			mountPoint=$(echo -n $result | awk '{print $2}')
			fileSystemType=$(echo -n $result | awk '{print $3}')
			if [[ $result =~ $searchTerm ]]; then
				printResults "" "ADD" "Potential Finding: The option $searchTerm was found for mount '$mountPoint' of type '$fileSystemType'. $reason"
			else
				printResults "" "ADD" "Not a Finding: The option $searchTerm was not found for mount '$mountPoint' of type '$fileSystemType'."
			fi
		done
	else
		for result in $results; do
			mountPoint=$(echo -n $result | awk '{print $2}')
			fileSystemType=$(echo -n $result | awk '{print $3}')
			if [[ ! $result =~ $searchTerm ]]; then
				printResults "" "ADD" "Potential Finding: The option $searchTerm was not found for mount '$mountPoint' of type '$fileSystemType'. $reason2"
			else
				printResults "" "ADD" "Not a Finding: The option $searchTerm was found for mount '$mountPoint' of type '$fileSystemType'."
			fi
		done
	fi
	
	
	IFS=$oldIFS

}

checkUserHomeDirExists () {
	questionNumber=$1
	results=$(pwck -r | grep -E "directory.*does not exist")
	oldIFS=$IFS
	IFS=$'\n'
	printf "Question Number $questionNumber: Review the following for users with non-existent home directories:\n"
	for result in $results; do 
		userName=$(echo -n $result | awk '{print $2}' | tr -d "'" | tr -d ":")
		userHomeDir=$(echo -n $result | awk '{print $4}' | tr -d "'")
		if [[ $(id -u $userName) -ge 1000 ]]; then
			printResults "" "ADD" "Finding: The home directory '$userHomeDir' for '$userName' doesn't exist."
		else
			printResults "" "ADD" "Potential Finding: The home directory '$userHomeDir' for '$userName' doesn't exist. If this is an interactive user, this is a finding."
		fi
	done
	IFS=$oldIFS
}

#todo automate permission checking
checkUserHomeDirPermissions () {
	questionNumber=$1
	oldIFS=$IFS
	IFS=$'\n'
	table="\tUser Directory Permission Owner Group\n"
	filter=""
	case $questionNumber in
		"41")
			printf "Question Number $questionNumber: Verify the assigned home directory of all local interactive users has a mode of '0750' or less.\n"
		;;
		"42")
			printf "Question Number $questionNumber: Verify the assigned home directory of all local interactive users are owned by the local user.\n"
		;;
		"96")
			printf "Question Number $questionNumber: Verify the assigned home directory of all local interactive users are group owned by the local user.\n"
		;;
		*)
		echo "Error"
		;;	
	esac

	for userLine in $(cat /etc/passwd); do
		userName=$(echo -n $userLine | awk -F':' '{print $1}')
		userHomeDir=$(echo -n $userLine | awk -F':' '{print $6}')
		if [[ ! $userHomeDir == "/" ]]; then
			if [[ $(id -u $userName) -ge 1000 ]] || [[ $(id -u $userName) -eq 0 ]]; then
				userHomeDirPermissions=$(stat $userHomeDir --printf "%n %a %U %G" 2>/dev/null)
				if (( ! $? )); then
					table="$table$userName $userHomeDirPermissions\n"
				elif (( $? )); then
					table="$table$userName $userHomeDir HomeFolderDoesNotExist\n"
				fi
			fi
		fi
	done
	printf "$table" | column -t
	IFS=$oldIFS
}

checkUserLocalInitialization () {
	questionNumber=$1
	oldIFS=$IFS
	IFS=$'\n'
	table="\tUser Directory Permission Owner Group\n"
	printf "Question Number $questionNumber: Verify that all local initialization files for all users have a mode of '0740' or less.\n"
	for userLine in $(cat /etc/passwd); do
		userName=$(echo -n $userLine | awk -F':' '{print $1}')
		userHomeDir=$(echo -n $userLine | awk -F':' '{print $6}')
		if [[ ! $userHomeDir == "/" ]]; then
			if [[ $(id -u $userName) -ge 0 ]]; then
				if [ -d $userHomeDir ];  then
					for file in $(find $userHomeDir -iname .[^.]* -type f -perm /0037); do
						filePermissions=$(stat $file --printf "%n %a %U %G" 2>/dev/null)
						table="$table$userName $filePermissions\n"
					done
				else
					echo -n "" >/dev/null
				fi
			fi
		fi
	done
	printf "$table" | column -t
	IFS=$oldIFS
}

checkNonPrivUserHomeFileSystems () {
	questionNumber=$1
	oldIFS=$IFS
	IFS=$'\n'
	table="\tUser Directory Permission Owner Group\n"
	printf "Question Number $questionNumber: Verify that all non-privileged user home directories are located on a separate file system/partition.\n"
	for userLine in $(cat /etc/passwd); do
		userName=$(echo -n $userLine | awk -F':' '{print $1}')
		userHomeDir=$(echo -n $userLine | awk -F':' '{print $6}')
		if [[ ! $userHomeDir == "/" ]]; then
			if [[ $(id -u $userName) -ge 0 ]]; then
				if [ -d $userHomeDir ];  then
					fileSystem=$(df $userHomeDir --output="file,target,fstype,source" 2>/dev/null | tail -n 1)
					table="$table$userName $fileSystem\n"
				else
					#echo -n "" >/dev/null
					table="$table$userName HomeFolderDoesNotExist\n"
				fi
			fi
		fi
	done
	printf "$table" | column -t
	IFS=$oldIFS
}


checkUserAccountSetting () {
	questionNumber=$1
	settingToCheck=$2
	case $settingToCheck in
		"EXPIRATION")
			printf "Question Number $questionNumber: Review the following password expiration information. If any temporary account has no expiration date set or does not expire within 72 hours, this is a finding.\n"
			for user in $localUsers; do
				expirationInfo=$(chage -l $user | grep -i "Account expires" | tr -d "\s\s")
				printResults "" "ADD" "$user\t$expirationInfo"
			done
		;;
		"UNIQUEUSERID")
			result=$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)
			if [[ -n $result ]]; then
				printResults "$questionNumber" "FIND" "One or more accounts were identified that share the same User ID:\n$result"
			else
				printResults "$questionNumber" "NFIND" ""
			fi
		;;
		"EMERACCOUNT")
			printf "Question Number $questionNumber: Review the following password expiration information. If any emergency account has no expiration data set or does not expire within 72 hours, this is a finding.\n"
			for user in $localUsers; do
				expirationInfo=$(chage -l $user | grep -i "Account expires" | tr -d "\s\s")
				printResults "" "ADD" "$user\t$expirationInfo"
			done
		;;
		"AUTHORIZED")
			printf "Question Number $questionNumber: Review the following accounts. If any account does not match existing approval documentation, this is a finding.\n"
			for user in $allLocalUsers; do
				printResults "" "ADD" "$user"
			done
		;;
		"UMASK")
			printf "Question Number $questionNumber: Review the following umask values for local interactive users. If any listed account has a umask value less restrictive than 0077, this is a finding.\n"
			for user in $localUsers; do
				result=$(su $user -c "umask")
				if [[ $(umask) != "0077" ]] && [[ $(umask) != "077" ]]; then
					printResults "" "ADD" "$user $result"
				fi
			done
		;;
		*)
			echo "Error"
			;;
	esac
}

checkGnomeSetting () {
	questionNumber=$1
	settingToCheck=$2
	case $settingToCheck in
		"SESSIONLOCK")
			result=$(gsettings get org.gnome.desktop.session idle-delay)
			if [[ $result =~ "uint32" ]]; then
				timeOut=$(echo -n $result | awk '{print $2}')
				if [[ $timeOut -eq 0 ]]; then
					printResults "$questionNumber" "FIND" "The automatic session lock for GUI is set to $timeOut seconds which is means that the session lock will not engage automatically."
				elif [[ $timeOut -le 900 ]]; then
					printResults "$questionNumber" "NFIND" ""
				else
					printResults "$questionNumber" "FIND" "The automatic session lock for GUI is set to $timeOut seconds which is greater than 15 minutes (900 seconds)."
				fi
			else
				printResults "$questionNumber" "PFIND" "The automatic session lock for GUI is not defined. If the system does not have any graphical user interface installed, this requirement is Not Applicable."
			fi
		;;
		"LOCKSESSION")
			result=$(gsettings get org.gnome.desktop.screensaver lock-delay)
			if [[ $result =~ "uint32" ]]; then
				lockTimeout=$(echo -n $result | awk '{print $2}')
				if [[ $lockTimeout -eq 0 ]]; then
					printResults "$questionNumber" "FIND" "The session lock timeout when activating the screensaver for the GUI is set to $lockTimeout seconds means that the session lock timeout will not engage automatically."
				elif [[ $lockTimeout -le 5 ]]; then
					printResults "$questionNumber" "NFIND" ""
				else
					printResults "$questionNumber" "FIND" "The session lock timeout when activating the screensaver for the GUI is set to $lockTimeout seconds which is greater than 5 seconds."
				fi
			else
				printResults "$questionNumber" "PFIND" "The session lock timeout when activating the screensaver for the GUI is not defined. If the system does not have any graphical user interface installed, this requirement is Not Applicable."
			fi
		;;
		"USERLIST")
			result=$(gsettings get org.gnome.login-screen disable-user-list)
			if [[ $result =~ "true" ]]; then
				printResults "$questionNumber" "NFIND" ""
			else
				printResults "$questionNumber" "PFIND" "The user logon list is not disabled If the system does not have a GUI, this requirement is Not Applicable"
			fi
		;;
		*)
			echo "Error"
			;;
	esac
}

checkShellUmask () {
	questionNumber=$1
	numberOfLines=$(grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile | grep -v "#" | wc -l)
	correctOccur=$(grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile | grep -v "#" | grep -c "077")
	if [[ $numberOfLines != $correctOccur ]]; then
		printResults "$questionNumber" "PFIND" "One or more umask values for an installed shell is not set to 077. If any listed shell has a umask value less restrictive than 077, this is a finding.\n"
		printResults "" "ADD" "$(grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile | grep -v "#")"
	else
		printResults "$questionNumber" "NFIND" ""
	fi
}

checkFailLockAuditing () {
	questionNumber=$1
	if [[ $release == "8.0" ]] || [[ $release == "8.1" ]]; then
		dir=$(grep -v "#" /etc/pam.d/system-auth | grep -i pam_faillock.so | grep -o -e "dir\s*=\s*\S*\s*" | sed s/"dir\s*=\s*"//)
		if [[ -z $dir ]]; then
			printResults "$questionNumber" "FIND" "The path to the faillock directory is not defined or is commented out."
		else
			result=$(grep $dir /etc/audit/audit.rules)
			if [[ -z $result ]]; then
				printResults "$questionNumber" "FIND" "The path to the faillock directory is not being audited."
			else
				if [[ $result =~ "-w" ]] && [[ $result =~ "-p\s*wa" ]]; then
					printResults "$questionNumber" "FIND" "The auditing settings for the faillock directory are incorrect.\n$result"
				else
					printResults "$questionNumber" "NFIND"
				fi
			fi
		fi
	else
		dir=$(grep -v "#" /etc/security/faillock.conf | grep -o -e "dir\s*=\s*\S*\s*" | sed s/"dir\s*=\s*"//)
		if [[ -z $dir ]]; then
			printResults "$questionNumber" "FIND" "The path to the faillock directory is not defined or is commented out."
		else
			result=$(grep $dir /etc/audit/audit.rules)
			if [[ -z $result ]]; then
				printResults "$questionNumber" "FIND" "The path to the faillock directory is not being audited."
			else
				if [[ $result =~ "-w" ]] && [[ $result =~ "-p\s*wa" ]]; then
					printResults "$questionNumber" "FIND" "The auditing settings for the faillock directory are incorrect.\n$result"
				else
					printResults "$questionNumber" "NFIND"
				fi
			fi
		fi
	fi
}


checkAideConfig () {
	questionNumber=$1
	sros=$2
	
	for sro in $sros; do
		result=$(grep $sro /etc/aide.conf)
		if [[ -n $result ]]; then
			printResults "$questionNumber" "REVIEW" "Review the following configuration line to confirm that it matches the required configuration for the SRO $sro:\n$result"
		else
			printResults "$questionNumber" "FIND" "The SRO $sro was not found in the /etc/aide.conf file."
		fi
	done
}

auditStorageSpace () {
	questionNumber=$1
	dir=$(grep -o -e "log_file\s*=\s*\S*\s*" /etc/audit/auditd.conf | grep -o -e "/\S*\s*")
	printResults "$questionNumber" "REVIEW" "Review the available free space on the partition where audit data is stored. The capacity of the partition must be large enough to store at least one week of audit records if the audit records are not immediately sent to the central audit record storage location. There should be at least 10 GB available.\n"
	df -h $dir
	printf "\n"
}

checkSyslogConfig () {
	questionNumber=$1
	results=$(grep -v "#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep @@)
	if [[ -n $results ]]; then
		printResults "$questionNumber" "REVIEW" "Verify that the remote logging server is receiving logs from this host. If the remote server is not configured correctly to receive logs from this host, this is a finding."
	else
		printResults "$questionNumber" "PFIND" "Rsyslog does not appear to be configured for remote logging. Ask the system administrator how the audit logs are off-loaded to a different system or media. If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding."
	fi
}

checkSyslogEncryption () {
	questionNumber=$1
	defaultNetstreamDriver=$(grep -v "#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep -i '$DefaultNetstreamDriver')
	sendStreamDriverMode=$(grep -v "#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep -i '$ActionSendStreamDriverMode')
	if [[ -n $defaultNetstreamDriver ]] && [[ -n $sendStreamDriverMode ]]; then
		if [[ ! $defaultNetstreamDriver =~ "gtls" ]] || [[ $sendStreamDriverMode != "1" ]]; then
			printResults "$questionNumber" "FIND" "The Default Netstream Driver or Action Send Stream Driver Mode isn't configured correctly. See configuration below:"
			printResults "" "ADD" "Default Netstream Driver: $defaultNetstreamDriver \t Action Send Stream Driver Mode: $sendStreamDriverMode"
		fi
	else
		printResults "$questionNumber" "FIND" "The Default Netstream Driver or Action Send Stream Driver Mode isn't configured."
	fi
}

checkSyslogRemoteVerification () {
	questionNumber=$1
	actionSendStreamDriver=$(grep -v "#" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2> /dev/null | grep -i '$ActionSendStreamDriverAuthMode')
	if [[ -n $actionSendStreamDriver ]]; then
		if [[ ! $actionSendStreamDriver =~ "x509/name" ]]; then
			printResults "$questionNumber" "FIND" "The Action Send Stream Driver Auth Mode isn't configured correctly. See configuration below:"
			printResults "" "ADD" "Action Send Stream Driver Auth Mode: $actionSendStreamDriver"
		fi
	else
		printResults "$questionNumber" "FIND" "The Action Send Stream Driver Auth Mode isn't configured."
	fi
}

chronyChecks () {
	questionNumber=$1
	maxpoll=$(grep -v "#" /etc/chrony.conf | grep -o -e "maxpoll\s*[0-9]*" | awk '{print $2}')
	if [[ -n $maxpoll ]]; then
		if [[ $maxpoll -gt "16" ]]; then
			printResults "$questionNumber" "FIND" "The maximum interval between time query requests sent to the server exceeds 24 hours. Maxpoll is configured to $maxpoll. Configure maxpoll to 16 or less."
		else
			printResults "$questionNumber" "NFIND"
		fi	
	else
		printResults "$questionNumber" "FIND" "Maxpoll is not configured. Configure maxpoll to 16 or less."
	fi
}

kernelModuleCheck () {
	questionNumber=$1
	modules=$2
	failIfFound=$3
	printResults "$questionNumber" "REVIEW" "Verify that all of the following checks for each module pass."
	if [ $failIfFound == "TRUE" ]; then
		for module in $modules; do
			printf "Kernel Module Name: $module\n"
			if grep $module /etc/modprobe.d/* | grep -q blacklist; then
				printResults "$questionNumber" "ADD" "PASS: Kernel Module Blacklisted"
			else
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module Not Blacklisted"
			fi
			
			if grep $module /etc/modprobe.d/* | grep -q -E "/bin/true|/bin/false"; then
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is setup for false install"
			else
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is not setup for false install"
			fi
			
			if lsmod | grep -q -i $module; then
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is Currently Loaded"
			else
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is not Currently Loaded"
			fi
			
			if [ "$(systemctl is-enabled $module 2>/dev/null)" == disabled -o "$(systemctl is-enabled $module 2>/dev/null)" == "masked" ]; then
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is Masked or Disabled"
			else
				systemctl is-enabled $module 2> ./tmp
				if echo "$(<./tmp)" | grep -q -i "No such file or directory"; then
					printResults "$questionNumber" "ADD" "INFO: No Such Kernel Module Found"
				else
					printResults "$questionNumber" "ADD" "FAIL: Kernel Module is not Masked or Disabled"
				fi
			fi
		done
	elif [ $failIfFound == "FALSE" ]; then
		for module in $modules; do
			printf "Kernel Module Name: $module\n"
			if grep -v "#" /etc/modprobe.d/* | grep $module | grep -q blacklist; then
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module Blacklisted"
			else
				printResults "$questionNumber" "ADD" "PASS: Kernel Module Not Blacklisted"
			fi
			
			if grep -v "#" /etc/modprobe.d/* | grep $module | grep -q -E "/bin/true|/bin/false"; then
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is setup for false install"
			else
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is not setup for false install"
			fi
			
			if lsmod | grep -q -i $module; then
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is Currently Loaded"
			else
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is not Currently Loaded"
			fi
			
			if [ "$(systemctl is-enabled $module 2>/dev/null >/dev/null)" == "disabled" -o "$(systemctl is-enabled $module 2>/dev/null >/dev/null)" == "masked" ]; then
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is Masked or Disabled"
			else
				systemctl is-enabled $module 2> ./tmp >./tmp
				if echo "$(<./tmp)" | grep -q -i "No such file or directory"; then
					printResults "$questionNumber" "ADD" "INFO: No Such Kernel Module Found"
				else
					printResults "$questionNumber" "ADD" "PASS: Kernel Module is not Masked or Disabled"
				fi
			fi
<<com2
			if [ "$(systemctl is-active $module 2>/dev/null)" == "inactive" ]; then
				printResults "$questionNumber" "ADD" "FAIL: Kernel Module is inactive."
			elif [ "$(systemctl is-active $module 2>/dev/null)" == "active" ]; then
				printResults "$questionNumber" "ADD" "PASS: Kernel Module is active."
			else
				systemctl is-active $module 2> ./tmp >./tmp
				if echo "$(<./tmp)" | grep -q -i "No such file or directory"; then
					printResults "$questionNumber" "ADD" "INFO: No Such Kernel Module Found"
				else
					printResults "$questionNumber" "ADD" "ERROR"
				fi
			fi
com2
		done
	fi

}

firewallCheck () {
	questionNumber=$1
	check=$2
	firewallState=$(firewall-cmd --state)
	if [[ "$firewallState" == "running" ]]; then
		case $check in
			"PPSM")
				activeZones=$(firewall-cmd --get-active-zones)
				results=$(firewall-cmd --list-all-zones)
				printResults "$questionNumber" "REVIEW" "Verify that the services allowed by the firewall match the program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). If there are additional ports, protocols, or services that are not in the PPSM CLSA, or their are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.\nActive Zones: $activeZones\nFirewall Rules:\n$results"
			;;
			"DEFAULTDENY")
				activeZones=$(firewall-cmd --get-active-zones | grep -v -e "^\s")
				if [[ -n $activeZones ]]; then
					for zone in $activeZones; do
						target=$(firewall-cmd --info-zone=$zone | grep -i "target")
						if [[ $target =~ "target:\s*DROP" ]]; then
							printResults "$questionNumber" "NFIND"
						else
							printResults "$questionNumber" "FIND" "Target is not set to DROP for this zone. Target is set to:'$target'"
						fi
					done
				else
					printResults "$questionNumber" "FIND" "No Active Firewall Zones"
				fi
			;;
			"RATELIMIT")
				firewallBackend=$(grep -v "#" /etc/firewalld/firewalld.conf | grep -i "firewallbackend" | sed s/"[Ff]irewall[Bb]ackend="//)
				if [[ $firewallBackend =~ "nftables" ]]; then
					printResults "$questionNumber" "NFIND"
				else
					printResults "$questionNumber" "FIND" "nftables is not set as the default backend for firewalld"
				fi
			;;
			*)
				echo "Error"
			;;
		esac
	else
		printResults "$questionNumber" "FIND" "Firewall is not running."
	fi
}

packageInstalled() {
	questionNumber=$1
	package=$2
	failIfFound=$3
	installationStatus=$(yum list installed $package* -q 2>/dev/null | tail -n+2)
	
	if [ $failIfFound == "TRUE" ]; then
		if [[ "$installationStatus" =~ "$package" ]]; then
			printResults "$questionNumber" "FIND" "Package was found to be installed."
			printResults "" "ADD" "Installed $package Package(s):\n$installationStatus"
		else
			printResults "$questionNumber" "NFIND"
		fi
	elif [ $failIfFound == "FALSE" ]; then
		if [[ "$installationStatus" =~ "$package" ]]; then
			printResults "$questionNumber" "NFIND"
			printResults "" "ADD" "Installed $package Package(s):\n$installationStatus"
		else
			printResults "$questionNumber" "FIND" "$package isn't installed."
		fi
	fi
}

checkForWirelessDevices () {
	questionNumber=$1
	questionableDevices=$(nmcli device status | tail -n+2 | grep -v -i -E "(ethernet|bridge|loopback)")
	if [[ -n $questionableDevices ]]; then
		printResults "$questionNumber" "REVIEW" "The following devices are not of type Ethernet, Bridge, or Loopback. Verify that none of the listed devices are wireless devices:\n$questionableDevices"
	else
		printResults "$questionNumber" "NFIND"
	fi

}

checkUSBGuard () {
	questionNumber=$1
	rules=$(usbguard list-rules)
	if usbguard list-rules &>/dev/null; then
		rules=$(usbguard list-rules)
		printResults "$questionNumber" "REVIEW" "Review the following rules to verify that unauthorized peripherals are being blocked:\n$rules"
	else
		printResults "$questionNumber" "FIND" "USBGuard is not configured properly to block unauthorized peripherals."
	fi
}

checkPromMode () {
	questionNumber=$1
	flaggedInterfaces=$(ip link | grep -i promisc)
	if [[ -n $flaggedInterfaces ]]; then
		printResults "$questionNumber" "PFIND" "The following network interfaces were found to be in promiscuous mode. If the use of these interfaces in promiscuous mode has not been documented and approved by the ISSO, this is a finding."
	else
		printResults "$questionNumber" "NFIND"
	fi
}

biosUEFICheck () {
	questionNumber=$1
	check=$2
	bootType=""
	test=""
	
	if [[ -e /boot/efi/EFI/redhat/grub.cfg ]]; then
		bootType="UEFI"
	elif [[ -e /boot/grub2/grub.cfg ]]; then
		bootType="BIOS"
	else
		bootType="BIOS"
	fi
	
	if [[ $questionNumber == "86" ]] && [[ $bootType == "BIOS" ]]; then
		check="NA"
	elif [[ $questionNumber == "87" ]] && [[ $bootType == "UEFI" ]]; then
		check="NA"
	elif [[ $questionNumber == "94" ]] && [[ $bootType == "BIOS" ]]; then
		check="NA"
	fi
	
	case $check in
		"SUPERUSERS")
			if [[ $bootType == "UEFI" ]]; then
				superUsers=$(grep -i -e "set\ssuperusers=.*" /boot/efi/EFI/redhat/grub.cfg | grep -o "\".*\"" | tr -d \")
			else
				superUsers=$(grep -i -e "set\ssuperusers=.*" /boot/grub2/grub.cfg | grep -o "\".*\"" | tr -d \")
			fi
			printResults "$questionNumber" "REVIEW" "Review the following identified superusers. If any superuser name is identical to an OS account name, this is a finding"
			for user in $superUsers; do
				if [[ "$allLocalUsers" =~ .*"$user".* ]]; then
					printResults "$questionNumber" "ADD" "FAIL: Superuser name $user is identical to an OS account name"
				else
					printResults "$questionNumber" "ADD" "PASS: Superuser name $user is not identical to an OS account name"
				fi
			done
		;;
		
		"UEFIPART")
			results=$(grep -v "#" /etc/fstab | grep "/boot/efi\s" | grep "nosuid")
			if [[ -n $results ]]; then
				printResults "$questionNumber" "NFIND"
			else
				printResults "$questionNumber" "FIND" "The /boot/efi partition either doesn't exist or is not mounted with the nosuid option."
			fi
		;;
		"NA")
			printResults "$questionNumber" "NOTAPPLICABLE"
		;;
		*)
			echo "Error"
		;;
	esac
}

sshCheck () {
	questionNumber=$1
	check=$2
	case $check in
		"TERMINATION")
			terminationTimeout=$(grep -r -v "#" /etc/ssh/sshd_config* | grep -i "ClientAliveInterval" | grep -o -e "[0-9]*")
			if [[ -n $terminationTimeout ]]; then
				if [[ $terminationTimeout -gt 600 ]]; then
					printResults "$questionNumber" "FIND" "Timeout is configured to $terminationTimeout which is greater than 10 minutes."
				elif [[ $terminationTimeout -eq 0 ]]; then
					printResults "$questionNumber" "FIND" "Timeout is disabled."
				else
					printResults "$questionNumber" "NFIND"
				fi
			else
				printResults "$questionNumber" "FIND" "Automatic Timeout for SSH Connections is not defined or is commented out."
			fi
		;;
		"CRYPTOPOL")
			cryptoPolicy=$(grep "CRYPTO_POLICY" /etc/sysconfig/sshd)
			if grep "CRYPTO_POLICY" /etc/sysconfig/sshd | grep -q "#"; then
				printResults "$questionNumber" "NFIND"
			else
				printResults "$questionNumber" "FIND" "SSHD must be configured to use system-wide crypto policies."
			fi
		;;
		"GSSAPI")
			gssapi=$(grep "CRYPTO_POLICY" /etc/sysconfig/sshd_config* | awk '{print $2}')
			if [[ $gssapi == "no" ]]; then
				printResults "$questionNumber" "NFIND"
			else
				printResults "$questionNumber" "FIND" "GSSAPI Authentication is either commented out, not defined, or configured to a value other than 'no'."
			fi
			
		;;
		*)
			echo "Error"
		;;
	esac
}

separatePartition () {
	questionNumber=$1
	partition=$2
	if grep -v "#" /etc/fstab | grep -q $partition; then
		printResults "$questionNumber" "NFIND"
	else
		printResults "$questionNumber" "FIND" "A separate partition for $partition has not been created."
	fi
}

checkPasswordRequirements () {
	questionNumber=$1
	case $questionNumber in
	"49") #needs testing on older RHEL
		if [[ $release == "8.0" ]] || [[ $release == "8.1" ]] || [[ $release == "8.2" ]]; then
			preauthfailResult=$(grep -v "#" /etc/pam.d/password-auth | grep -i -E "auth\s+required\s+pam_faillock\.so\s+preauth.*dir=/.*")
			authfailResult=$(grep -v "#" /etc/pam.d/password-auth | grep -i -E "auth\s+required\s+pam_faillock\.so\s+authfail.*dir=/.*")
			if [[ -n $preauthfailResult ]] && [[ -n $authfailResult ]]; then
				preauthfailResult=$(grep -v "#" /etc/pam.d/system-auth | grep -i -E "auth\s+required\s+pam_faillock\.so\s+preauth.*dir=/.*")
				authfailResult=$(grep -v "#" /etc/pam.d/system-auth | grep -i -E "auth\s+required\s+pam_faillock\.so\s+authfail.*dir=/.*")
				if [[ -n $preauthfailResult ]] && [[ -n $authfailResult ]]; then
					printResults "$questionNumber" "NFIND"
				else
					printResults "$questionNumber" "FIND" "The fail lock directory contents are not configured to persist after a reboot."
				fi
			else
					printResults "$questionNumber" "FIND" "The fail lock directory contents are not configured to persist after a reboot."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	"50")
		if ! [[ $release == "8.0" ]] && ! [[ $release == "8.1" ]] && ! [[ $release == "8.2" ]]; then
			result=$(grep -v "#" /etc/security/faillock.conf | grep -i -o -E "dir\s*=\s*/.*")
			if [[ -n $result ]]; then
				directory=$(echo -n "$result" | sed s/"dir\s*=\s*"//)
				if [[ $directory == "/var/run/faillock" ]]; then
					printResults "$questionNumber" "FIND" "Directory is configured to the default directory '$directory'. This is a finding."
				else
					printResults "$questionNumber" "NFIND"
				fi
			else
				printResults "$questionNumber" "FIND" "Local lockouts must persist after a reboot."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	"126")
		result=$(grep -E "password\s+required\s+pam_pwquality\.so" /etc/pam.d/system-auth)
		if [[ -n $result ]]; then
			printResults "$questionNumber" "NFIND"
		else
			printResults "$questionNumber" "FIND" "The operating system doesn't use 'pwquality' to enforce the password complexity rules."
		fi
	;;
	"127")
		if [[ $release == "8.0" ]] || [[ $release == "8.1" ]] || [[ $release == "8.2" ]] || [[ $release == "8.3" ]]; then
			result=$(grep -E "password\s+required\s+pam_pwquality\.so\s+retry=" /etc/pam.d/system-auth)
			if [[ -n $result ]]; then
				retryCount=$(echo "$result" | grep -i -o -E "retry=[0-9]+" | grep -o -E "[0-9]+")
				if [[ $retryCount == 0 ]]; then
					printResults "$questionNumber" "FIND" "The password complexity module is set to unlimted retries."
				elif [[ $retryCount -le 3 ]]; then
					printResults "$questionNumber" "NFIND"
				else
					printResults "$questionNumber" "FIND" "The password complexity module is not configured to three retries or less."
				fi
			else
				printResults "$questionNumber" "FIND" "The password complexity module is not configured to limit retries."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	"128")
		if [[ $release == "8.0" ]] || [[ $release == "8.1" ]] || [[ $release == "8.2" ]] || [[ $release == "8.3" ]]; then
			result=$(grep -E "password\s+required\s+pam_pwquality\.so\s+retry=" /etc/pam.d/password-auth)
			if [[ -n $result ]]; then
				retryCount=$(echo "$result" | grep -i -o -E "retry=[0-9]+" | grep -o -E "[0-9]+")
				if [[ $retryCount == 0 ]]; then
					printResults "$questionNumber" "FIND" "The password complexity module is set to unlimted retries."
				elif [[ $retryCount -le 3 ]]; then
					printResults "$questionNumber" "NFIND"
				else
					printResults "$questionNumber" "FIND" "The password complexity module is not configured to three retries or less."
				fi
			else
				printResults "$questionNumber" "FIND" "The password complexity module is not configured to limit retries."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	"129")
		if [[ $release == "8.0" ]] || [[ $release == "8.1" ]] || [[ $release == "8.2" ]] || [[ $release == "8.3" ]]; then
			printResults "$questionNumber" "NOTAPPLICABLE"
		else
			result=$(grep -r -E "retry\s*=\s*" /etc/security/pwquality.conf* | grep -v "#")
			lineCount=$(printf "$result" | wc -l)
			if [[ $lineCount -gt 1 ]]; then
				printResults "$questionNumber" "FIND" "Conflicting results for retry count."
			elif [[ -n $result ]]; then
				retryCount=$(echo "$result" | grep -i -o -E "retry\s*=\s*[0-9]+" | grep -o -E "[0-9]+")
				if [[ $retryCount == 0 ]]; then
					printResults "$questionNumber" "FIND" "The password complexity module is set to unlimted retries."
				elif [[ $retryCount -le 3 ]]; then
					printResults "$questionNumber" "NFIND"
				else
					printResults "$questionNumber" "FIND" "The password complexity module is not configured to three retries or less."
				fi
			else
				printResults "$questionNumber" "FIND" "The password complexity module is not configured to limit retries."
			fi
		fi
	;;
	"130")
		result=$(grep -i -E "password.*pam_pwhistory.so.*remember=" /etc/pam.d/system-auth | grep -v "#")
		passwordHistory=$(echo "$result" | grep -i -o -E "remember\s*=\s*[0-9]+" | grep -o -E "[0-9]+")
		if [[ $passwordHistory == 0 ]] || ! [[ -n $passwordHistory ]]; then
			printResults "$questionNumber" "FIND" "The password history is disabled."
		elif [[ $passwordHistory -lt 5 ]]; then
			printResults "$questionNumber" "FIND" "The password history is set to remember $passwordHistory passwords which is less than 5 passwords."
		else
			printResults "$questionNumber" "NFIND"
		fi
	;;
	*)
		echo "Error."
	;;
	esac
	
}

verifyLogging () {
	questionNumber=$1
	logEvents=$2
	destinationLog=$3
	printResults "$questionNumber" "REVIEW" "Review the following checks. If any check comes back as a FAIL, this is a finding."
	for event in $logEvents; do
		result=$(grep -v "#" /etc/rsyslog.conf | grep "$event")
		event=$(printf $event | tr -d '\\')
		if [[ -n $result ]]; then
			if [[ $result =~ $destinationLog ]]; then
				printResults "$questionNumber" "ADD" "PASS: The event $event is being logged by rsyslog to the log file '$destinationLog'."
			else
				printResults "$questionNumber" "ADD" "FAIL: The event $event is not being logged by rsyslog to the log file '$destinationLog'."
			fi
		else
			printResults "$questionNumber" "ADD" "FAIL: The event $event is not being logged by rsyslog to any log file."
		fi
	done
}

worldWritableInitializationFiles () {
	questionNumber=$1
	oldIFS=$IFS
	printResults "$questionNumber" "REVIEW" "Review the following list for any world-writable files referenced in user initialization scripts. If there are any FAILs, this is a finding."
	IFS=$'\n'
	partitions=$(grep -v "#" /etc/fstab | awk '{print $2}' | grep "/")
	for partition in $partitions; do
		worldWriteableFiles=$(find $partition -xdev -type f -perm -0002 -print)
		if [[ -n $worldWriteableFiles ]]; then
			for file in $worldWriteableFiles; do
				isReferenced=$(grep -H "$file" /home/*/.* 2>/dev/null)
				if [[ -n $isReferenced ]]; then
					referencedFile=$(printf "$isReferenced" | awk -F ":" '{print $1}')
					printResults "$questionNumber" "ADD" "FAIL: The world-writable file '$file' was found referenced in user initialization file '$referencedFile'"
				fi
			done
		else
			printf ""
			#printResults "$questionNumber" "ADD" "PASS: No world-writable files found on partition $partition"
		fi
	done
	IFS=$oldIFS
}

dnsConfiguration () {
	questionNumber=$1
	isNSSUsingDNS=$(grep -i -E "hosts:.*dns" /etc/nsswitch.conf)
	if [[ -n isNSSUsingDNS ]]; then
		dnsServersCount=$(grep -v "#" /etc/resolv.conf | grep -i "nameserver" | wc -l)
		if [[ $dnsServersCount -ge 2 ]]; then
			printResults "$questionNumber" "NFIND"
		else
			printResults "$questionNumber" "FIND" "The host is configured to use DNS for Name Service Switch (NSS); however, there are less than two DNS nameservers defined in /etc/resolv.conf."
		fi
	else
		isResolvEmpty=$(grep -v "#" /etc/resolv.conf | wc -l)
		if [[ -n $isResolvEmpty ]]; then
			printResults "$questionNumber" "NFIND"
		else
			printResults "$questionNumber" "FIND" "Local host authentication is being used; however, /etc/resolv.conf is not empty."
		fi
	fi
	
}

checkUserInitializationPathsVars () {
	questionNumber=$1
	oldIFS=$IFS
	IFS=$'\n'
	for userLine in $(cat /etc/passwd); do
		userName=$(echo -n $userLine | awk -F':' '{print $1}')
		userHomeDir=$(echo -n $userLine | awk -F':' '{print $6}')
		if [[ ! $userHomeDir == "/" ]]; then
			if [[ $(id -u $userName) -ge 1000 ]] || [[ $(id -u $userName) -eq 0 ]]; then
				if [[ -d $userHomeDir ]];  then
					externalPathVars=$(grep -i -h -o "path=.*" $userHomeDir/.* 2>/dev/null | tr -d '"' | sed "s/[Pp][Aa][Tt][Hh]=//g" | sed "s|\$HOME|$userHomeDir|g")
					IFS=':'
					for pathVar in $externalPathVars; do
						if [[ $pathVar == "$userHomeDir"* ]] || [[ $pathVar == "\$PATH"* ]]; then
							printf ""
						else
							printResults "$questionNumber" "FIND" "$pathVar is located outside of user $userName home directory $userHomeDir."
						fi
					done
					IFS=$'\n'
				else
					printResults "$questionNumber" "PFIND" "User home directory defined in /etc/passwd does not exist."
				fi
			fi
		fi
	done
	IFS=$oldIFS
}

smartCardCheck () {
	questionNumber=$1
	pamCertAuth=$(grep -v "#" /etc/sssd/sssd.conf | grep -i -E "pam_cert_auth\s+=\s+true")
	systemAuthCertAuth=$(grep -v "#" /etc/pam.d/system-auth | grep -i -E "pam_sss\.so\s(try|require)_cert_auth")
	smartcardAuthCertAuth=$(grep -v "#" /etc/pam.d/smartcard-auth | grep -i -E "pam_sss\.so\s(try|require)_cert_auth")
	
	if [[ -n $pamCertAuth ]] && [[ -n $systemAuthCertAuth ]] && [[ -n $smartcardAuthCertAuth ]]; then
		printResults "$questionNumber" "NFIND"
	else
		printResults "$questionNumber" "PFIND" "Smart card logon for multifactor authentication for access to interactive acccounts is not implemented. If the system administrator demonstrates the use of an approved alternative multifactor authentication method, this requirement is not applicable-otherwise this is a finding."
	fi
}

cachedCredentialsCheck () {
	questionNumber=$1
	cachedCredentialsAllowed=$(grep -v "#" /etc/sssd/sssd.conf | grep -i -E "cache_credentials\s+=\s+true")
	if [[ -n $cachedCredentialsAllowed ]]; then
		cachedCredentialsExpiration=$(grep -v "#" /etc/sssd/sssd.conf | grep -i -E "offline_credentials_expiration\s+=\s+1")
		if [[ -n $cachedCredentialsExpiration ]]; then
			printResults "$questionNumber" "NFIND"
		else
			printResults "$questionNumber" "FIND" "SSSD must prohibit the use of cached authentications after one day."
		fi
	else
		printResults "$questionNumber" "NFIND"
	fi
}

verifyPamFailLockinUse () {
	questionNumber=$1
	case $questionNumber in
	"97")
		if ! [[ $release == "8.0" ]] && ! [[ $release == "8.1" ]]; then
			systemAuthResult=$(grep -v "#" /etc/pam.d/system-auth | grep -i -E "pam_faillock\.so\s+preauth")
			if [[ -n $systemAuthResult ]]; then
					printResults "$questionNumber" "NFIND"
			else
					printResults "$questionNumber" "FIND" "The operating system does not configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	"98")
		if ! [[ $release == "8.0" ]] && ! [[ $release == "8.1" ]]; then
			systemAuthResult=$(grep -v "#" /etc/pam.d/password-auth | grep -i -E "pam_faillock\.so\s+preauth")
			if [[ -n $systemAuthResult ]]; then
					printResults "$questionNumber" "NFIND"
			else
					printResults "$questionNumber" "FIND" "The operating system does not configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file."
			fi
		else
			printResults "$questionNumber" "NOTAPPLICABLE"
		fi
	;;
	*)
		echo "Error"
	;;
	esac
}

preventGNOMEOverrides () {
	questionNumber=$1
	case $questionNumber in
	"102")
		systemDBProfile=$(grep -v "#" /etc/dconf/profile/user | grep -i -E "system-db:.*" | awk -F ":" '{print $2}')
		numberOfProfiles=$(echo -n "$systemDBProfile" | wc -w)
		if [[ $numberOfProfiles -gt 1 ]]; then
			printResults "$questionNumber" "REVIEW" "$numberOfProfiles system-db profiles were identified as being in use. Review the following to verify that there are no conflicting settings. At least one check must return PASS."
			for profile in $systemDBProfile; do
				isLocked=$(grep -v "#" /etc/dconf/db/$profile.d/locks/* 2>/dev/null| grep -i "/org/gnome/desktop/session/idle-delay")
				if [[ -n $isLocked ]]; then
						printResults "$questionNumber" "ADD" "PASS: Lock setting for idle-delay was found in profile $profile."
				else
						printResults "$questionNumber" "ADD" "REVIEW: Lock setting for idle-delay was not found in profile $profile."
				fi
			done
			else
			isLocked=$(grep -v "#" /etc/dconf/db/$systemDBProfile.d/locks/* | grep -i "/org/gnome/desktop/session/idle-delay")
			if [[ -n $isLocked ]]; then
					printResults "$questionNumber" "NFIND"
			else
					printResults "$questionNumber" "PFIND" "The operating system does not prevent a user from overriding the session idle-delay setting for the GUI. If the system does not have a GUI installed, this requirement is Not Applicable."
			fi
		fi
	;;
	"103")
		systemDBProfile=$(grep -v "#" /etc/dconf/profile/user | grep -i -E "system-db:.*" | awk -F ":" '{print $2}')
		numberOfProfiles=$(echo -n "$systemDBProfile" | wc -w)
		if [[ $numberOfProfiles -gt 1 ]]; then
			printResults "$questionNumber" "REVIEW" "$numberOfProfiles system-db profiles were identified as being in use. Review the following to verify that there are no conflicting settings. At least one check must return PASS."
			for profile in $systemDBProfile; do
				isLocked=$(grep -v "#" /etc/dconf/db/$profile.d/locks/* 2>/dev/null| grep -i "/org/gnome/desktop/screensaver/lock-enabled")
				if [[ -n $isLocked ]]; then
						printResults "$questionNumber" "ADD" "PASS: Lock setting for screensaver lock-enabled was found in profile $profile."
				else
						printResults "$questionNumber" "ADD" "REVIEW: Lock setting for screensaver lock-enabled was not found in profile $profile."
				fi
			done
			else
			isLocked=$(grep -v "#" /etc/dconf/db/$systemDBProfile.d/locks/* | grep -i "/org/gnome/desktop/screensaver/lock-enabled")
			if [[ -n $isLocked ]]; then
					printResults "$questionNumber" "NFIND"
			else
					printResults "$questionNumber" "PFIND" "The operating system does not prevent a user from overriding the screensaver lock-enabled setting for the GUI. If the system does not have a GUI installed, this requirement is Not Applicable."
			fi
		fi
	;;
	*)
		echo "Error"
	;;
	esac
}

<<com
checkForSetting "automaticloginenable=false" "/etc/gdm/custom.conf" "1"
checkUnitFile "ctrl-alt-del.target" "masked" "1" "2" "inactive"
checkForSetting "logout=''" "/etc/dconf/db/local.d/*" "3"
checkUpdateHistory "4"
checkDriveEncryption "5"
checkForBanner "banner" "/etc/ssh/sshd_config" "189" "6"
checkSettingContains "banner-message-text" "/etc/dconf/db/local.d/*" "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS)" "7"
checkSettingContains "USG" "/etc/issue" "You are accessing a U.S. Government (USG) Information System (IS)" "8"
verifyLogging "9" "auth.* authpriv.* daemon.*" "/var/log/secure"
checkDODRootCA "10"
checkSSHKeyPasswords "11"
checkCommandOutput "Enforcing" "getenforce" "Enforcing" "12"
checkFilePermissions "/" "d" "( -perm -0002 -a ! -perm -1000 )" "TRUE" "13" "are world-writable and do not have the sticky bit set." "FALSE"
checkForSetting "oMACs=hmac-sha2-512,hmac-sha2-256" "/etc/crypto-policies/back-ends/opensshserver.config" "14"
checkForSetting "oCiphers=aes256-ctr,aes192-ctr,aes128-ctr" "/etc/crypto-policies/back-ends/opensshserver.config" "15"
checkForSetting ".include /etc/crypto-policies/back-ends/opensslcnf.config" "/etc/pki/tls/openssl.cnf" "16"
checkForSetting "+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:+COMP-NULL:" "/etc/crypto-policies/back-ends/gnutls.config" "17"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "f" "-perm /022" "TRUE" "18" "are group or world-writable." "TRUE"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "f" "! -user root" "TRUE" "19" "are not owned by root." "TRUE"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "f" "! -group root" "TRUE" "20" "are not group owned by root." "TRUE"
checkCronjob "aide" "21"
checkForSetting "certificate_verification" "/etc/sssd/" "22"
checkCommandOutput "PIV-II\s*" "opensc-tool --list-drivers" "Personal Identity Verification Card" "23"
checkCommandOutput "NX\s.Execute\sDisble.\sprotection:\s" "dmesg" "active" "24" "nx" "cat /proc/cpuinfo" "nx"
checkCommandOutput "page_poison=" "grub2-editenv list" "1" "25"
checkCommandOutput "vsyscall=" "grub2-editenv list" "none" "26a"
checkForSetting "GRUB_CMDLINE_LINUX=\"vsyscall=none\"" "/etc/default/grub" "26b"
checkCommandOutput "slub_debug=" "grub2-editenv list" "P" "27a"
checkForSetting "GRUB_CMDLINE_LINUX=\"slub_debug=P\"" "/etc/default/grub" "27b"
checkSettingContains "/home" "/etc/fstab" "nosuid" "28" #may need to revist this one to consider home directories not mounted at /home
checkSettingContains "/home" "/etc/fstab" "noexec" "29" #may need to revist this one to consider home directories not mounted at /home
checkFileSystemTable "30" "nodev" "FALSE" "Confirm that this mounted file system does not refer to removable media."
checkFileSystemTable "31" "noexec" "FALSE" "Confirm that this mounted file system does not refer to removable media."
checkFileSystemTable "32" "nosuid" "FALSE" "Confirm that this mounted file system does not refer to removable media."
worldWritableInitializationFiles "33"
checkUnitFile "kdump.service" "masked" "1" "34" "inactive"
checkUnitFile "systemd-coredump.socket" "masked" "1" "35" "inactive"
dnsConfiguration "36"
checkUserInitializationPathsVars "37"
checkFilePermissions "/" "d" "-perm -0002 -uid +999 -print" "TRUE" "38" "are world-writable and are not owned by a system account." "FALSE"
checkFilePermissions "/" "d" "-perm -0002 -gid +999 -print" "TRUE" "39" "are world-writable and are not group owned by a system account." "FALSE"
checkUserHomeDirExists "40"
checkUserHomeDirPermissions "41"
checkUserHomeDirPermissions "42"
checkUserHomeDirExists "43"
checkUserLocalInitialization "44"
checkFilePermissions "/" "" "-nouser" "TRUE" "45" "do not have a valid owner." "FALSE"
checkFilePermissions "/" "" "-nogroup" "TRUE" "46" "do not have a valid owner." "FALSE"
checkNonPrivUserHomeFileSystems "47"
checkUserAccountSetting "48" "EXPIRATION"
checkPasswordRequirements "49"
checkPasswordRequirements "50"
checkCommandOutput "true" "gsettings get org.gnome.desktop.screensaver lock-enabled" "true" "51"
checkForSetting "removal-action='lock-screen'" "/etc/dconf/db/*" "52"
checkGnomeSetting "53" "SESSIONLOCK"
#20230522
checkForSetting "lock-after-time 900" "/etc/tmux.conf" "54"
checkForSetting "/org/gnome/desktop/screensaver/lock-delay" "/etc/dconf/db/local.d/locks/*" "55"
needtoRevist "56"
checkUserAccountSetting "57" "UNIQUEUSERID"
smartCardCheck "58"
checkUserAccountSetting "59" "EMERACCOUNT"
cachedCredentialsCheck "60"
checkUserAccountSetting "61" "AUTHORIZED"
checkUserAccountSetting "62" "UMASK"
checkShellUmask "63"
checkForSetting "/var/log/cron" "/etc/rsyslog.conf" "64"
checkSettingContains "postmaster:\s*root$" "/etc/aliases" "postmaster:" "65"
checkFailLockAuditing "66"
checkAideConfig "67" "/usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/ausearch /usr/sbin/aureport /usr/sbin/autrace /usr/sbin/rsyslog /usr/sbin/augenrules"
auditStorageSpace "68"
checkSyslogConfig "69"
checkSyslogEncryption "70"
checkSyslogRemoteVerification "71"
chronyChecks "72"
kernelModuleCheck "73" "uvcvideo" "TRUE"
firewallCheck "74" "PPSM"
kernelModuleCheck "75" "autofs" "TRUE"
firewallCheck "76" "DEFAULTDENY"
packageInstalled "77" "firewalld" "FALSE"
checkForWirelessDevices "78"
packageInstalled "79" "fapolicyd" "FALSE"
checkUSBGuard "80"
firewallCheck "81" "RATELIMIT"
kernelModuleCheck "82" "debug-shell" "TRUE"
packageInstalled "83" "xorg-x11-server" "TRUE"
checkPromMode "84"
checkForSetting "banner-message-enable=true" "/etc/dconf/db/local.d/*" "85"
biosUEFICheck "86" "SUPERUSERS"
biosUEFICheck "87" "SUPERUSERS"
checkForSetting "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency" "/usr/lib/systemd/system/emergency.service" "88"
checkSettingContains "password sufficient pam_unix.so" "/etc/pam.d/system-auth" "sha512" "89"
sshCheck "90" "TERMINATION"
sshCheck "91" "CRYPTOPOL"
sshCheck "92" "GSSAPI"
separatePartition "93" "/var/tmp"
biosUEFICheck "94" "UEFIPART"
checkFilePermissions "/home/" "f" "-perm /0027" "TRUE" "95" "have a mode more permissive than 0750" "FALSE" "\.[^\/]+$"
checkUserHomeDirPermissions "96"
verifyPamFailLockinUse "97"
verifyPamFailLockinUse "98"
checkGnomeSetting "99" "LOCKSESSION"
checkGnomeSetting "100" "USERLIST"
packageInstalled "101" "tmux" "FALSE"
preventGNOMEOverrides "102"
preventGNOMEOverrides "103"
checkUnitFile "auditd.service" "enabled" "0" "104" "active"
checkForSetting "space_left_action = email" "/etc/audit/auditd.conf" "105"
checkUnitFile "firewalld.service" "enabled" "0" "106" "active"
checkUnitFile "fapolicyd.service" "enabled" "0" "107" "active"
checkForSetting "permissive = 0" "/etc/fapolicyd/fapolicy.conf" "108"
checkForSetting "deny perm=any all : all" "/etc/fapolicyd/fapolicyd.rules" "108"
checkForSetting "deny perm=any all : all" "/etc/fapolicyd/compiled.rules" "108"
packageInstalled "109" "usbguard" "FALSE"
checkUnitFile "usbguard.service" "enabled" "0" "110" "active"
packageInstalled "111" "openssh-server" "FALSE"
needtoRevist "112"
needtoRevist "113"
needtoRevist "114"
needtoRevist "115"
packageInstalled "116" "mcafeetp" "FALSE"
checkUnitFile "mfetpd.service" "enabled" "0" "116" "active"
needtoRevist "117"
needtoRevist "118"
needtoRevist "119"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "d" "-perm /0022" "TRUE" "120" "have a mode more permissive than 0755" "FALSE"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "d" "! -user root" "TRUE" "121" "are not owned by root." "FALSE"
checkFilePermissions "/lib /lib64 /usr/lib /usr/lib64" "d" "! -group root" "TRUE" "122" "are not group owned by root." "FALSE"
needtoRevist "123"
needtoRevist "124"
needtoRevist "125"
checkPasswordRequirements "126"
checkPasswordRequirements "127"
checkPasswordRequirements "128"
checkPasswordRequirements "129"
checkPasswordRequirements "130"
checkCommandOutputImproved "131" "systemctl get-default" "multi-user.target" "If the ISSO lacks a documented requirement for a graphical user interface, this is a finding."
needtoRevist "132"
checkForSetting "CRYPTO_POLICY='-oKexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'" "/etc/crypto-policies/back-ends/opensshserver.config" "133"
checkUnitFile "rngd" "enabled" "0" "134" "active"
needtoRevist "135"
needtoRevist "136"
needtoRevist "137"
needtoRevist "138"
needtoRevist "139"
needtoRevist "140"
needtoRevist "141"
packageInstalled "142" "rng-tools" "FALSE"
com
<<zom
verifyLogging "9" "auth\.\* authpriv\.\* daemon\.\*" "/var/log/secure"
worldWritableInitializationFiles "33"
dnsConfiguration "36"
checkUserInitializationPathsVars "37"
checkPasswordRequirements "49"
checkPasswordRequirements "50"
zom
smartCardCheck "58"
cachedCredentialsCheck "60"
verifyPamFailLockinUse "97"
verifyPamFailLockinUse "98"
preventGNOMEOverrides "102"
preventGNOMEOverrides "103"