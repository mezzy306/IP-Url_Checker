import argparse
import csv
import requests
import validators
import json

VT_API_KEY = 'Your Virus Total Apikey'
ABUSEIPDB_API_KEY = 'Your AbuseIPDB Apikey'

def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        json_dict = result['data']['attributes']['last_analysis_stats']
        malicious = json_dict['malicious']
        total = sum(json_dict.values())
        print({ip},"malicious :",malicious,"Out of",total)
        return {'Malicious': malicious, 'Total': total}
        #return response.json()
    else:
        return None

def scan_url(url):
    if not validators.url(url):
        return None
    params = {'apikey': VT_API_KEY, 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.status_code == 200:
        result = response.json()
        malicious = result['positives']
        total = result['total']
        print(params['resource'],"malicious",malicious,"Out Of",total)
        return {'Malicious': malicious, 'Total' : total}
    else:
        return None


def check_abuseip(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        
        return response.json()
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
                    results.append({'IP/URL': line, 'VT Score': ip_result,'Total Scans': ip_result['Total']})
                if args.check_url:
                 url_result = scan_url(line)
                if url_result:
                    results.append({'IP/URL': line, 'VT Score': url_result['Malicious'], 'Total Scans': url_result['Total']})
            else:
                url_result = scan_url(line)
                if url_result:
                    results.append({'IP/URL': line, 'VT Score': url_result, 'AbuseIPDB Score': None})
            if args.check_ip:
                abuseip_result = check_abuseip(line)
                if abuseip_result:
                    for result in results:
                        if result['IP/URL'] == line:
                            result['AbuseIPDB Score'] = abuseip_result['data']['abuseConfidenceScore']

    with open(args.output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP/URL', 'VT Score', 'AbuseIPDB Score'])
        for result in results:
            writer.writerow([result['IP/URL'], result['VT Score'], result['AbuseIPDB Score']])

if __name__ == '__main__':
    main()
