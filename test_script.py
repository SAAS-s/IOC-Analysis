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
def test_query_virustotal():
    ioc = "8.8.8.8"  # Example IP
    result = query_virustotal(ioc, ioc_type='ip')
    assert result is not None
    assert 'ioc' in result
    assert 'type' in result
    assert 'malicious_count' in result
    assert 'reputation' in result

#Test for files with yara
def test_scan_files_with_yara():
     rule_file = "path_to_test_yara_rules.yar"  # Path to a test Yara rules file
     file_paths = ["path_to_test_file"]  # Path to test files
     results = scan_files_with_yara(rule_file, file_paths)
     assert len(results) > 0
     assert isinstance(results[0], tuple)

if __name__=="__main__":
    pytest.main()
