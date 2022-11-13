# Jorge E. Campo II
# 11/12/2022

# Virus Total API v3 bash script to generate report

# Can delete this variable if you export it into system
APIKEY="<API KEY HERE>"

# Case and Switch for cmd flags
case $1 in
	-f)
	type="files";;
	-u)
	type="urls";;
	-d)
	type="domains";;
	-ip)
	type="ip_addresses";;
	*)
	echo "usage: ./virustotal.sh [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> "
	exit ;;
esac

# Checks if object is none
if [[ $2 == "" ]]; then
	echo "usage: ./virustotal.sh [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> "
	exit
fi

# Sends the request
curl --request GET \
     --url https://www.virustotal.com/api/v3/$type/{$2} \
     --header 'x-apikey: '$APIKEY


