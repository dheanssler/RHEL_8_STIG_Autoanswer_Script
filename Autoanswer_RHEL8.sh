#/bin/bash
#Check if script is being run as root.
if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  printf "Script executed as root...\n"
else
  IAMROOT="0"
  printf "WARNING: This script has not been executed as root.\n"
fi

#Change directory to script directory.
parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"

#Ensure Path Variable Contains sbin
PATH=$PATH:/usr/sbin

#Get List of Local Users
localUsers=$(cat /etc/passwd | grep -Ev "nologin|false|sync|shutdown|true|halt")


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
	unitFileCheck=$(sudo systemctl is-enabled $1)
	checkReturnCode=$?
	
	if [ $unitFileCheck == $expectedStatus ] && [ $checkReturnCode -eq $expectedReturnCode ]; then
		printResults "$questionNumber" "NFIND" ""
	else
		printResults "$questionNumber" "FIND" "The unit file '$unitFileName' was not $expectedStatus.\n"
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
	
	#echo $key
	#echo $command
	#echo $matchString
	#echo $result
	
	if [[ $result =~ "$matchString" ]]; then
		printResults "$questionNumber" "NFIND" ""
	else
		if [[ $key2 ]]; then
			result=$($command2 2>&1 | grep -E $key2)
			if [[ $result =~ "$matchString2" ]]; then
				printResults "$questionNumber" "NFIND" ""
			else
				printResults "$questionNumber" "FIND" "The output of '$command' did not return the expected result '$key$matchString'\n\tThe result was '$result'"
			fi
		else
			printResults "$questionNumber" "FIND" "The output of '$command' did not return the expected result '$key$matchString'\n\tThe result found was '$result'"
		fi
		
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
	results=""
	
	if [ $followSymLinks == "TRUE" ]; then
		result=$(find -L $startDirectory -type $type $permissions2 -print 2>/dev/null)
	else
		result=$(find $startDirectory -type $type $permissions2 -print 2>/dev/null)	
	fi
	
	if [[ $result ]]; then
		if [ $failIfFound == "TRUE" ]; then
			printResults "$questionNumber" "FIND" "One or more objects of type '$type' within directory '$startDirectory' were identified that $6\nMatching Objects:\n\t$result"
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


checkForSetting "automaticloginenable=false" "/etc/gdm/custom.conf" "1"
checkUnitFile "ctrl-alt-del.target" "masked" "1" "2"
checkForSetting "logout=''" "/etc/dconf/db/local.d/*" "3"
checkUpdateHistory "4"
checkDriveEncryption "5"
checkForBanner "banner" "/etc/ssh/sshd_config" "189" "6"
checkSettingContains "banner-message-text" "/etc/dconf/db/local.d/*" "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS)" "7"
checkSettingContains "USG" "/etc/issue" "You are accessing a U.S. Government (USG) Information System (IS)" "8"
needtoRevist "9"
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
needtoRevist "33"
checkUnitFile "kdump.service" "masked" "1" "34"
checkUnitFile "systemd-coredump.socket" "masked" "1" "35"
needtoRevist "36"
needtoRevist "37"
checkFilePermissions "/" "d" "-perm -0002 -uid +999 -print" "TRUE" "38" "are world-writable and are not owned by a system account." "FALSE"
checkFilePermissions "/" "d" "-perm -0002 -gid +999 -print" "TRUE" "39" "are world-writable and are not group owned by a system account." "FALSE"