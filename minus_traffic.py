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

# Main function to analyze pcap file and cross-reference IoCs
def analyze_pcap_and_cross_reference(pcap_file):
    # Extract IoCs from the pcap file
    iocs = extracts_iocs_from_pcap(pcap_file)
    
    # Cross-reference IPs with VirusTotal
    for ip in iocs['ips']:
        print(f"Checking IP: {ip}")
        query_virustotal(ip, ioc_type='ip')
    
    # Cross-reference domains with VirusTotal
    for domain in iocs['domains']:
        print(f"Checking Domain: {domain}")
        query_virustotal(domain, ioc_type='domain')

# test case
if __name__ == "__main__":
    pcap_file = "path_to_your_pcap_file.pcap"  # providing pcap file path
    analyze_pcap_and_cross_reference(pcap_file)