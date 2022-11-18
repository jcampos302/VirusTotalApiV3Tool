# Jorge E. Campos II
# 11/13/2022

# Virus Total API v3 python script to a small generate report

import sys
from time import sleep
import requests as requests

# Test Hash = 92d37a92138659fa75f45ccb87242910
# Don't share API Key
API_KEY = '<API KEY HERE>'

# API Link and Header
URL = "https://www.virustotal.com/api/v3/"
API_HEADER = {'x-apikey': API_KEY}


def parse_data(r):
    report = r.json()

    print("\n*** Virus Total Report ***\n")

    try:
        common_name = report['data']['attributes']['names']
        for i in common_name:
            print(i)
    except KeyError:
        pass
    try:
        url_name = report['data']['attributes']['url']
        print("URL Link Name = " + str(url_name).replace(".", "[.]"))
    except KeyError:
        pass
    try:
        threat_label = report['data']['attributes']['popular_threat_classification']['suggested_threat_label']
        print("\nSuggested Threat Label: " + threat_label)
    except KeyError:
        pass
    try:
        threat_names = report['data']['attributes']['threat_names']
        print("\nSuggested Threat Label: " + str(threat_names))
    except KeyError:
        pass
    try:
        id_name = report['data']['id']
        print("URL Link Name = " + str(id_name).replace(".", "[.]"))
    except KeyError:
        pass
    try:
        country = report['data']['attributes']['country']
        print("Country: " + country)
    except KeyError:
        pass
    # Print Analysis Stats
    try:
        analysis_stats = report['data']['attributes']['last_analysis_stats']
        print("\nAnalysis Stats:")
        print("Harmless: " + str(analysis_stats['harmless']))
        print("Suspicious:" + str(analysis_stats['suspicious']))
        print("Malicious: " + str(analysis_stats['malicious']))
        print("Undetected: " + str(analysis_stats['undetected']) + "\n")
    except KeyError:
        print("\nUnable to print Analysis Stats")


# Function Space
def get_request(dir_type, item):
    r = requests.get(URL + dir_type + item, headers=API_HEADER)
    return r


def check_response(r):
    if r.status_code == 200:
        return r
    else:
        print("!!!Error!!!\n")
        print(r.text)
        exit()


def hash_upload(item):
    dir_type = "files/"
    r = get_request(dir_type, item)
    r = check_response(r)
    parse_data(r)


def url_upload(item):
    dir_type = "urls/"

    # To get url Id:
    # item = base64.urlsafe_b64encode(url_link.encode()).decode().strip("=")

    r = get_request(dir_type, item)
    r = check_response(r)
    parse_data(r)


def domain_upload(item):
    dir_type = "domains/"
    r = get_request(dir_type, item)
    r = check_response(r)
    parse_data(r)


def ip_address_upload(item):
    dir_type = "ip_addresses/"
    r = get_request(dir_type, item)
    r = check_response(r)
    parse_data(r)


def file_loop_ips(item):
    f1 = open(item, 'r')
    lines = f1.readlines()
    count = 0
    # Strips the newline character
    for line in lines:
        ip_address_upload(line.strip())
        count += 1
        if count == 5:
            sleep(60)
            count = 0


# Checks if object is empty
if len(sys.argv) < 3:
    print("usage: ./virustotal.py [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> ")
    exit()

# Flag match case
match sys.argv[1]:
    case "-f":
        hash_upload(sys.argv[2])
    case "-u":
        url_upload(sys.argv[2])
    case "-d":
        domain_upload(sys.argv[2])
    case "-ip":
        ip_address_upload(sys.argv[2])
    case "-l":
        file_loop_ips(sys.argv[2])
    case _:
        print("usage: ./virustotal.py [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> ")
        exit()
