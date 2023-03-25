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
	searchString=$1
	searchLocation=$2
	matchString=$3
	questionNumber=$4
<<com
	echo $searchString
	echo $searchLocation
	echo $matchString
	echo $questionNumber
com
	searchResults=$(sudo grep -ih $searchString $searchLocation 2>/dev/null)

	if [ "${searchResults^^}" == "${matchString^^}" ]; then
		printf "Question Number $questionNumber: Not a Finding\n"
	else
		printf "Question Number $questionNumber: Finding\n"
		printf "\tReason: The setting '$matchString' was not found in the configuration file '$searchLocation'.\n"
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
	sshDirectories=$(find / -type d -name .ssh 2>/dev/null)
	for sshDirectory in $sshDirectories; do
		printf "$sshDirectory\n"
	done
	#TODO Foreach loop to go through each directory
}

checkForSetting "automaticloginenable" "/etc/gdm/custom.conf" "automaticloginenable=false" "1"
checkUnitFile "ctrl-alt-del.target" "masked" "1" "2"
checkForSetting "logout" "/etc/dconf/db/local.d/*" "logout=''" "3"
checkUpdateHistory
checkDriveEncryption
checkForBanner "banner" "/etc/ssh/sshd_config" "189" "6"
checkSettingContains "banner-message-text" "/etc/dconf/db/local.d/*" "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS)" "7"
checkSettingContains "USG" "/etc/issue" "You are accessing a U.S. Government (USG) Information System (IS)" "8"
unclearRequirementNeedtoRevist "9"
checkDODRootCA "10"
checkSSHKeyPasswords "11"