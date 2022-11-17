# Jorge E. Campos II
# 11/13/2022

# Virus Total API v3 python script to a small generate report

import sys
import requests as requests

# Test Hash = 92d37a92138659fa75f45ccb87242910
# Don't share API Key
API_KEY = '<API KEY HERE>'

# API Link and Header
URL = "https://www.virustotal.com/api/v3/"
API_HEADER = {'x-apikey': API_KEY}


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
    file_report_parse(r)


def file_report_parse(r):
    report = r.json()
    analysis_stats = report['data']['attributes']['last_analysis_stats']
    common_name = report['data']['attributes']['names']
    threat_label = report['data']['attributes']['popular_threat_classification']['suggested_threat_label']

    print("Hash Analysis Report:\n")
    for i in common_name:
        print(i)
    print("\nSuggested Threat Label: " + threat_label)
    print("\nAnalysis Stats:")
    print("Harmless: " + str(analysis_stats['harmless']))
    print("Suspicious:" + str(analysis_stats['suspicious']))
    print("Malicious: " + str(analysis_stats['malicious']))
    print("Undetected: " + str(analysis_stats['undetected']))


def url_upload(item):
    dir_type = "urls/"

    # To get url Id:
    # item = base64.urlsafe_b64encode(url_link.encode()).decode().strip("=")

    r = get_request(dir_type, item)
    r = check_response(r)
    url_report_parse(r)


def url_report_parse(r):
    report = r.json()
    url_name = report['data']['attributes']['url']
    threat_names = report['data']['attributes']['threat_names']
    analysis_stats = report['data']['attributes']['last_analysis_stats']

    print("URL Analysis Report:\n")
    print("URL Link Name = " + str(url_name).replace(".", "[.]"))
    print("\nSuggested Threat Label: " + str(threat_names))
    print("\nAnalysis Stats:")
    print("Harmless: " + str(analysis_stats['harmless']))
    print("Suspicious:" + str(analysis_stats['suspicious']))
    print("Malicious: " + str(analysis_stats['malicious']))
    print("Undetected: " + str(analysis_stats['undetected']))


def domain_upload(item):
    dir_type = "domains/"
    r = get_request(dir_type, item)
    r = check_response(r)
    domain_report_parse(r)


def domain_report_parse(r):
    report = r.json()
    id_name = report['data']['id']
    analysis_stats = report['data']['attributes']['last_analysis_stats']

    print("Domain Analysis Report:\n")
    print("URL Link Name = " + str(id_name).replace(".", "[.]"))
    print("\nAnalysis Stats:")
    print("Harmless: " + str(analysis_stats['harmless']))
    print("Suspicious:" + str(analysis_stats['suspicious']))
    print("Malicious: " + str(analysis_stats['malicious']))
    print("Undetected: " + str(analysis_stats['undetected']))


def ip_address_upload(item):
    dir_type = "ip_addresses/"
    r = get_request(dir_type, item)
    r = check_response(r)
    ip_address_report_parse(r)


def ip_address_report_parse(r):
    report = r.json()
    id_name = report['data']['id']
    analysis_stats = report['data']['attributes']['last_analysis_stats']
    country = report['data']['attributes']['country']

    print("IP Address Analysis Report:\n")
    print("IP Address = " + str(id_name).replace(".", "[.]"))
    print("Country: " + country)
    print("\nAnalysis Stats:")
    print("Harmless: " + str(analysis_stats['harmless']))
    print("Suspicious:" + str(analysis_stats['suspicious']))
    print("Malicious: " + str(analysis_stats['malicious']))
    print("Undetected: " + str(analysis_stats['undetected']))


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
    case _:
        print("usage: ./virustotal.py [-f: files or hash | -u: urls | -d: domains | -ip: ip address] <object> ")
        exit()
