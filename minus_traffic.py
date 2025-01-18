#importing important libraries
import pyshark
import pytest
import requests
import yara
import json
from datetime import datetime

#use your virustotal api key
API_KEY = ""

#output file for splunk ingestion
OUTPUT_FILE = "ioc_results.json"

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
            malicious_count = stats.get('malicious',0)
            reputation = result['data']['attributes'].get('reputation', 'N/A')
            return {
                'ioc': ioc,
                'type': ioc_type,
                'malicious_count': malicious_count,
                'reputation': reputation,
                'timestamp': datetime.utcnow().isoformat()
            }
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

#function to save results in the json format for integration with splunk 
def save_results(results, output_file):
    try:
        with open(output_file,"w") as json_file:
            json.dump(results, json_file, indent=4)
        print(f"[INFO] Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

# Function to create a dashboard using Matplotlib
def create_dashboard(ioc_data):
    malicious_counts = [ioc['malicious'] for ioc in ioc_data if ioc]
    labels = [ioc['ioc'] for ioc in ioc_data if ioc]
    
    # Create a bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(labels, malicious_counts, color='red')
    plt.xlabel("IoCs (IPs/Domains)")
    plt.ylabel("Malicious Count")
    plt.title("Malicious IoCs Detected by VirusTotal")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

# Main function to analyze pcap file and cross-reference IoCs
def analyze_and_save(pcap_file, yara_rule_file=None, file_paths=None):
    # Extract IoCs from the pcap file
    iocs = extracts_iocs_from_pcap(pcap_file)
    results = []

    # Query VirusTotal for IoCs and collect data
   
    for ip in iocs['ips']:
        print(f"Checking IP: {ip}")
        result = query_virustotal(ip, ioc_type='ip')
        if result:
            results.append(result)

    for domain in iocs['domains']:
        print(f"Checking Domain: {domain}")
        result = query_virustotal(domain, ioc_type='domain')
        if result:
            results.append(result)

    # Optionally scan files with Yara
    if yara_rule_file and file_paths:
        yara_results = scan_files_with_yara(yara_rule_file, file_paths)
        results.extend({'file_scan': r} for r in yara_results)

    save_results(results, OUTPUT_FILE)
    
    # Generate a dashboard
    create_dashboard(ioc_data)

# Test case
if __name__ == "__main__":
    pcap_file = "path_to_your_pcap_file.pcap"  # Provide your pcap file path
    yara_rule_file = "path_to_yara_rules.yar"  # Provide your Yara rules file path
    file_paths = ["path_to_file1", "path_to_file2"]  # Provide file paths for Yara scanning
    
    analyze_and_visualize(pcap_file, yara_rule_file, file_paths)