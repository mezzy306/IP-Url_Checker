import argparse
import csv
import requests
import validators
import json
from time import sleep,time
import sys

VT_API_KEY = 'ecf38a6bfba54b21f4545447cff7ac90610a883978941708c49276c173128ce4'
ABUSEIPDB_API_KEY = '6fda25db2df06fa2948a4d3484a6b6973f9445b999edadf0ba0428550c6b2e953437b35b40d14001'
ThreatBook_API_KEY = '7671980d35754d25a240aa36048c7056005d6ac0e8d740dc983eea61d30d1c5d'

def scan_ip(ip):
    
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    linked = f"https://www.virustotal.com/gui/ip-address/{ip}"
    print("virustotal",response)
    sleep(3)
    if response.status_code == 200:
        result = response.json()
        json_dict = result['data']['attributes']['last_analysis_stats']
        malicious = json_dict['malicious']
        total = sum(json_dict.values())
        #permalink = result['data']['links']['self']
        print({ip},"malicious :",malicious,"Out of",total)
        return {'Malicious': malicious, 'Total': total, 'Permalink': linked}
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
    sleep(4)
    result = response.json()
    resource_id = result['data']['id'].split('-')[1]
    response = requests.get(url_report_url + resource_id, headers=headers)
    #print(response.json())
    analysis = response.json()['data']
    malicious = analysis['attributes']['last_analysis_stats']['malicious']
    AllTotal = analysis['attributes']['last_analysis_stats']
    id = analysis['id']
    total = sum(AllTotal.values())
    #permalink = analysis['links']['self']
    linked = f'https://www.virustotal.com/gui/url/{id}'
    print(url, "malicious", malicious, "out of", total)
    return {'Malicious': malicious, 'Total': total, 'Permalink': linked}
    

def check_abuseip(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    linked = f'https://abuseipdb.com/check/{ip}'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    print("abuseip",response)
    if response.status_code == 200:
        result = response.json()
        score = result['data']['abuseConfidenceScore']
        return {'Score': score, 'Url' : linked}
    else:
        return None   
    
def geo_ip(ip):
    url = f'https://api.threatbook.io/v1/community/ip?apikey={ThreatBook_API_KEY}&resource={ip}'
    response = requests.get(url) 
    print("geoip",response)
    if response.status_code == 200:
        result = response.json()['data']['basic']['location']
        country = result['country']
        prov = result['province']
        city = result['city']
        result = country,prov,city
        return result
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
    start = time()
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
            if args.check_ip:
                geo_ip_result = geo_ip(line)

                if geo_ip_result:
                    for result in results:
                        if result['IP/URL'] == line:
                            result['Location'] = geo_ip_result
                             
           
                            

    with open(args.output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP/URL', 'Malicious','Total', 'AbuseIPDB Score','VTPermalink','ABPermalink','Location'])
        for result in results:
                writer.writerow([result['IP/URL'], result['Malicious'],result['Total'], result['AbuseIPDB Score'],result['VTPermalink'],result['ABPermalink'],result['Location']])
    print("---------------------------------------\nTotal Time Elapsed: " + str(round(time() - start, 2)))
    
if __name__ == '__main__':
    main()
   
