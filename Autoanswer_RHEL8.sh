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
checkForSetting () {
	oldIFS=$IFS
	IFS=$'\n'
	searchString=$1
	searchLocation=$2
	questionNumber=$3

	#echo $searchString
	#echo $searchLocation
	#echo $questionNumber

	searchResults=$(sudo grep -ioh $searchString $searchLocation 2>/dev/null)
	IFS=$oldIFS
	#echo $searchResults

	if [ "${searchResults^^}" == "${searchString^^}" ]; then
		printf "Question Number $questionNumber: Not a Finding\n"
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The setting '$searchString' was not found in the configuration file '$searchLocation'.\n"
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
		printf "Question Number $questionNumber: Not a Finding\n"
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The unit file '$unitFileName' was not $expectedStatus.\n"
	fi
}

checkUpdateHistory () {
	dnfHistory=$(dnf history list | head -n 8 )
	printf "Question Number 4: Review the following update history and confirm that updates are being performed in accordance with program requirements.\n"
	printf "$dnfHistory\n"
}

checkDriveEncryption () {
	allBlockDevices=$(blkid | awk '{print substr($1,1,length($1)-1)}')
	nonLuksBlockDevices=$(blkid | grep -v "crypto_LUKS" | awk '{print substr($1,1,length($1)-1)}')
	luksBlockDevices=$(blkid | grep "crypto_LUKS" | awk '{print substr($1,1,length($1)-1)}')
	printf "Question Number 5: Review the following block devices. Ask the system administrator about any devices indicated as not being encrypted. If there is no evidence that a partition or block device is encrypted, this is a finding. \n"
	if [ -x "$(command -v cryptsetup)" ]; then
		for blockDevice in $luksBlockDevices; do
			luksDumpResults=$(sudo cryptsetup luksDump $blockDevice)
			luksCipher=$(echo -n "$luksDumpResults" | grep "Cipher:")
			luksKeyLength=$(echo "$luksDumpResults" | grep -E -o "Cipher key:\s[0-9]+" | grep -E -o "[0-9]+")
			if [[ $luksCipher =~ "aes" ]]; then
				if [ "$luksKeyLength" -gt "511" ]; then
					printf "\tNOT A FINDING: $blockDevice is encrypted with AES-256 bit encryption.\n"
				else
					printf "\tPOTENTIAL FINDING: $blockDevice effective encryption key size is less than 256 bits.\n"
				fi
			else
				printf "\tPOTENTIAL FINDING: $blockDevice is not encrypted using an AES algorithm.\n"
			fi
		done
	else
		printf "POTENTIAL FINDING: CRYPTSETUP COMMAND NOT FOUND\n"
	fi
	
	for blockDevice in $nonLuksBlockDevices; do
		printf "\tPOTENTIAL FINDING: $blockDevice is not encrypted.\n"
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
			printf "Question Number $questionNumber: Not a Finding\n"
		else
			printf "Question Number $questionNumber: Finding \n"
			printf "\tReason: The word count ($bannerWordCount) of the file does not match the word count of the standard DOD Notice and Consent Banner.\n"
		fi
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The path to $searchTerm was not set in the configuration file $searchLocation.\n"
	fi
}

checkSettingContains () {
	searchString=$1
	searchLocation=$2
	matchString=$3
	questionNumber=$4

	searchResults=$(sudo grep -ih $searchString $searchLocation 2>/dev/null)

	if [[ "${searchResults^^}" =~ "${matchString^^}" ]]; then
		printf "Question Number $questionNumber: Not a Finding\n"
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The setting '$matchString' was not found in the configuration file '$searchLocation'.\n"
	fi
}

unclearRequirementNeedtoRevist () {
	printf "Question $1: The requirements for meeting this STIG aren't clear.\n"
}

checkDODRootCA () {
	questionNumber=$1
	searchResults=$(sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem 2>/dev/null)
	if (( "$(echo -n $searchResults | wc -c)" > 0 )); then
		printf "Question Number $questionNumber: Review the following certificate information to confirm that the root ca is a DoD-issued certificate with a valid date.\n"
	else
		printf "Question Number $questionNumber: POTENTIAL FINDING: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.\n"
	fi
}

checkSSHKeyPasswords () {
	printf "Question Number 11: Review the following files identified as potential private keys. If there are any private keys that are not password protected, this is a finding. \n"
	sshDirectories=$(find / -type d -name .ssh 2>/dev/null)
	for sshDirectory in $sshDirectories; do
		for file in $(ls $sshDirectory | grep -v .pub); do
			result=$(ssh-keygen -y -P "" -f "$sshDirectory/$file" 2>&1)
			if [[ $result =~ "incorrect passphrase" ]]; then
				printf "\tNOT A FINDING: $sshDirectory/$file is password protected\n"
			elif [[ $result =~ "invalid format" ]]; then
				echo -n ""
			elif [[ $result =~ "ssh-" ]]; then
				printf "\tFinding: $sshDirectory/$file is not password protected\n"
			elif [[ $result =~ "UNPROTECTED PRIVATE KEY FILE" ]]; then
				printf "\tFinding: $sshDirectory/$file has incorrect file permissions\n"
			else
				printf "\tPOTENTIAL FINDING: Output not recognized for $sshDirectory/$file. Verify manually.\n"
			fi
		done
	done
}

#"key" "command" "expected result" "questionNumber"
checkCommandOutput () {
	key=$1
	command=$2
	matchString=$3
	questionNumber=$4
	result=$($command 2>&1 | grep $key)
	
	if [[ $result =~ "$matchString" ]]; then
		printf "Question Number $questionNumber: Not a Finding\n"
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The output of '$command' did not return the expected result '$matchString'\n\tThe result was '$result'\n"
	fi
}

# "startDirectory" "type" "permissions" "failIfFound" "questionNumber"
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
	
	echo $result
	
	if [[ $result ]]; then
		if [ $failIfFound == "TRUE" ]; then
			printf "Question Number $questionNumber: Finding\n"
			printf "\tReason: One or more objects of type '$type' within directory '$startDirectory' were identified that $6\nMatching Objects:\n\t$result\n"
		else
			printf "Question Number $questionNumber: Not a Finding\n"
		fi
	else #not found
		if [ $failIfFound == "TRUE" ]; then
			printf "Question Number $questionNumber: Not a Finding\n"
		else
			printf "Question Number $questionNumber: Finding\n"
			printf "\tReason: No objects of type '$type' within directory '$startDirectory' were identified that $6\n"
		fi
	fi
}

#TODO: Currently only checks via crontab. Need to include checks within /etc/cron.*
checkCronjob () {
	name=$1
	questionNumber=$2
	cronJobs=$(crontab -l | grep -v "#" | grep -i "$name")
	if [ -x "$(command -v $name)" ]; then
		printf "Question Number $questionNumber: Review the following and validate that the cronjobs are configured per organization standards\n$cronJobs\n"
		if [[ $cronJobs ]]; then
			printf "Cronjobs identified via crontab -l for the root user:\n\t$cronJobs\n"
		else
			cronJobs=$(grep -rH $name /etc/cron.*)
			if [[ $cronJobs ]]; then
				printf "Cronjobs identified via via /etc/cron.* files:\n\t$cronJobs\n"
			else
				printf "Question Number $questionNumber: Finding\n"
				printf "\tReason: No cronjob for $name was found\n"
			fi
		fi
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The binary $name does not appear to be installed or available in the current PATH variable\n"
	fi
	
}

checkForSetting "automaticloginenable=false" "/etc/gdm/custom.conf" "1"
checkUnitFile "ctrl-alt-del.target" "masked" "1" "2"
checkForSetting "logout=''" "/etc/dconf/db/local.d/*" "3"
#checkUpdateHistory
checkDriveEncryption
checkForBanner "banner" "/etc/ssh/sshd_config" "189" "6"
checkSettingContains "banner-message-text" "/etc/dconf/db/local.d/*" "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS)" "7"
checkSettingContains "USG" "/etc/issue" "You are accessing a U.S. Government (USG) Information System (IS)" "8"
unclearRequirementNeedtoRevist "9"
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