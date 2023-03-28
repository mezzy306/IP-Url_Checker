import argparse
import csv
import requests
import validators
import json
from time import sleep

VT_API_KEY = 'Your_VirusTotal_Key'
ABUSEIPDB_API_KEY = 'Your_AbuseDb_Key'

def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        json_dict = result['data']['attributes']['last_analysis_stats']
        malicious = json_dict['malicious']
        total = sum(json_dict.values())
        permalink = result['data']['links']['self']
        print({ip},"malicious :",malicious,"Out of",total)
        return {'Malicious': malicious, 'Total': total, 'Permalink': permalink}
    else:
        return None

def scan_url(url):
    if not validators.url(url):
        return None
    url_scan_url = 'https://www.virustotal.com/api/v3/urls'
    url_report_url = 'https://www.virustotal.com/api/v3/urls/'
    headers = {
        'x-apikey': VT_API_KEY
    }
    response = requests.post(url_scan_url, headers=headers, data={'url': url})
    result = response.json()
    resource_id = result['data']['id'].split('-')[1]
    response = requests.get(url_report_url + resource_id, headers=headers)
    analysis = response.json()['data']
    sleep(4)
    malicious = analysis['attributes']['last_analysis_stats']['malicious']
    AllTotal = analysis['attributes']['last_analysis_stats']
    total = sum(AllTotal.values())
    permalink = analysis['links']['self']
    print(url, "malicious", malicious, "out of", total)
    return {'Malicious': malicious, 'Total': total, 'Permalink': permalink}


def check_abuseip(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        score = result['data']['abuseConfidenceScore']
        return {'Score': score, 'Url' : url}
    else:
        return None

def main():
    parser = argparse.ArgumentParser(description='Scan a list of IPs and URLs.')
    parser.add_argument('input_file', help='The path to the input file.')
    parser.add_argument('output_file', help='The path to the output file.')
    parser.add_argument('--check-ip', action='store_true', help='Check IPs using the AbuseIPDB API.')
    parser.add_argument('--check-url', action='store_true', help='Check URLs using the VirusTotal API.')
    args = parser.parse_args()

    results = []
    url_result = None
    with open(args.input_file, 'r') as f:
        for line in f:
            line = line.strip()
            if args.check_ip:
                ip_result = scan_ip(line)
                if ip_result:
                    results.append({'IP/URL': line, 'Malicious': ip_result['Malicious'],'Total': ip_result['Total'],'VTPermalink': ip_result['Permalink']})
                if args.check_url:
                 url_result = scan_url(line)
                if url_result:
                    results.append({'IP/URL': line, 'Malicious': url_result['Malicious'], 'Total': url_result['Total'],'VTPermalink': ip_result['Permalink']})
            else:
                url_result = scan_url(line)
                if url_result:
                    results.append({'IP/URL': line, 'Malicious': url_result['Malicious'],'Total': url_result['Total'],'VTPermalink': url_result['Permalink'],'AbuseIPDB Score': None ,'ABPermalink' : None})
            if args.check_ip:
                abuseip_result = check_abuseip(line)
                if abuseip_result:
                    for result in results:
                        if result['IP/URL'] == line:
                            result['AbuseIPDB Score'] = abuseip_result['Score']
                            result['ABPermalink'] = abuseip_result['Url']

    with open(args.output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP/URL', 'Malicious','Total', 'AbuseIPDB Score','VTPermalink','ABPermalink'])
        for result in results:
                writer.writerow([result['IP/URL'], result['Malicious'],result['Total'], result['AbuseIPDB Score'],result['VTPermalink'],result['ABPermalink']])

if __name__ == '__main__':
    main()
