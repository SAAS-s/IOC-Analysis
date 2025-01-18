#importing important libraries
import pyshark
import pytest
import requests
import yara

API_KEY = ""

#function to extract IPs and domains from pcap file
def extracts_iocs_from_pcap(pcap_file):
    iocs = {'ips': set(), 'domains':set()}


    #Parse the pcap file with Pyshark 
    capture = pyshark.FileCapture(pcap_file)

    #Iterate over packets and extract IPs and domains
    for packet in capture:
        if hasattr(packet, 'ip'):
            #Extract IP addresses from IP layer
            if hasattr(packet.ip, 'src') and packet.ip.src:
                iocs['ips'].add(packet.ip.src)
            if hasattr(packet.ip, 'dst') and packet.ip.dst:
                iocs['ips'].add(packet.ip.dst)
        
        if hasattr(packet, 'dns'):
            #Extract domains from DNS layer
            if hasattr(packet.dns, 'qry_name') and packet.dns.qry_name:
                iocs['domains'].add(packet.dns.qry_name)

    return iocs


# Function to query VirusTotal for IoCs
def query_virustotal(ioc, ioc_type='ip'):
    url = f'https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}'
    
    headers = {
        'x-apikey': API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            # Check if the IOC is flagged
            stats = result['data']['attributes']['last_analysis_stats'] 
            malicious = ['malicious'] 
            reputation = result['data']['attributes'].get('reputation', 'N/A')
            print(f"[INFO] {ioc}: Malicious={malicious}, Reputation={reputation}")
            return {'ioc': ioc, 'malicious': malicious, 'reputation': reputation}
        else:
            print(f"Error querying VirusTotal for {ioc}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return None

# Function to scan files using Yara
def scan_files_with_yara(rule_file, file_paths):
    # Compile Yara rules
    rules = yara.compile(filepath=rule_file)
    results = []

    for file_path in file_paths:
        try:
            matches = rules.match(file_path)
            if matches:
                print(f"[ALERT] File {file_path} matched Yara rules: {matches}")
                results.append((file_path, matches))
            else:
                print(f"File {file_path} is clean.")
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
    return results


# Main function to analyze pcap file and cross-reference IoCs
