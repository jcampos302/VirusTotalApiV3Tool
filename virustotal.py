# Jorge E. Campos II
# 11/13/2022

# Virus Total API v3 python script to a small generate report


import sys
import requests as requests

# Don't share API Key
APIKEY = '<API KEY HERE>'

# API Link and Header
url = "https://www.virustotal.com/api/v3/"
headers = {'x-apikey' : APIKEY}

# Flag match case
match sys.argv[1]:
    case "-f":
        temp = "files/"
    case "-u":
        temp = "urls/"
    case "-d":
        temp = "domains/"
    case "-ip":
        temp = "ip_addresses/"
    case _:
        print("usage: ./virustotal.py [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> ")
        exit()

# Checks if object is empty
if sys.argv[2] == "":
    print("usage: ./virustotal.py [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> ")
    exit()

# Sends the request
r = requests.get(url+temp+sys.argv[2], headers=headers)

data = r.json()
temp = data['data']['attributes']['last_analysis_stats']

# Filters and Print Data
print("Analysis Statistics")
print("Harmless: " + str(temp['harmless']))
print("Unsupported: " + str(temp['type-unsupported']))
print("Suspicious:" + str(temp['suspicious']))
print("Malicious: " + str(temp['malicious']))
print("Undetected: " +str(temp['undetected']))

