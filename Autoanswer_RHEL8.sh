#Check if script is being run as root.
if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  printf "Script executed as root..."
else
  IAMROOT="0"
  printf "WARNING: This script has not been executed as root. "
fi