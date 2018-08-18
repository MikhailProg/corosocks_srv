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
		if ($0 ~ /^ *$/ || $0 ~ /^#/)
			continue
		db[$1] = $2
	}

	if (user in db) {
		cmd = "printf \"" pass "\" | '$md5cmd'"
		if (cmd | getline > 0 && db[user] == $1)
			ok = 1
		close(cmd)
	}
}

END {
	ok ? passed() : failed()
}'

# A simple db in here-document.
# userN -- md5(passN)
# $ printf 'passN' | md5sum

user1 a722c63db8ec8625af6cf71cb8c2d939
user2 c1572d05424d0ecb2a65ec6a82aeacbf
user3 3afc79b597f88a72528e864cf81856d2

EOF

