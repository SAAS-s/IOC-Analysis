import pytest
from minus_traffic import extracts_iocs_from_pcap, query_virustotal, scan_files_with_yara

#Test for extracts from pcap function
def test_extracts_iocs_from_pcap():
    pcap_file = "path_to_test_pcap.pcap" 
    iocs = extracts_iocs_from_pcap(pcap_file)
    assert 'ips' in iocs
    assert 'domains' in iocs
    assert len(iocs['ips']) > 0
    assert len(iocs['domains']) > 0

#Test for query virustotal function