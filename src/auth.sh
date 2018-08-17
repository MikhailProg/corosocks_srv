#!/bin/sh -e

# The server provides the following variables:
#
# $PROXY_USER_IP
# $PROXY_USER
# $PROXY_PASS
#
# Print "y" to stdout if all checks are passed other result
# means a fail.
#

# Uncomment the export to debug this script by hand in terminal.
#export PROXY_USER_IP="127.0.0.1" PROXY_USER="user1" PROXY_PASS="pass1"
test "$PROXY_USER_IP" -a "$PROXY_USER" -a "$PROXY_PASS" || exit 1

if [ "$(uname -s)" = "Darwin" ]; then
	md5cmd=md5
else
	md5cmd=md5sum
fi

cat << EOF | awk '

function passed()
{
	print "y"
	exit 0
}

function failed()
{
	exit 1
}

BEGIN {
	ip   = ENVIRON["PROXY_USER_IP"]
	user = ENVIRON["PROXY_USER"]
	pass = ENVIRON["PROXY_PASS"]
	ok   = 0
	
	while (getline > 0) {
		if ($0 ~ /^$/ || $0 ~ /^#/)
			continue
		db[$1] = $2
	}

	if (user in db) {
		cmd = "echo " pass " | '$md5cmd'"
		if (cmd | getline > 0 && db[user] == $1)
			ok = 1
	}
}

END {
	ok ? passed() : failed()
}'

# A simple db in here-document.
# userN -- md5(passN)

user1 eeff5809b250d691acf3a8ff8f210bd9
user2 e83cf18ac2b92787c3f4c20aae5f097e
user3 b879e7867c53e22d9fbb4cce52984227

EOF

