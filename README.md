# IOC-Analysis

This project is designed to analyze network traffic captured in pcap files, extract Indicators of Compromise `(IoCs)`, and cross-reference them with VirusTotal for threat intelligence. Additionally, it integrates Yara for file scanning and saves the results in `JSON` and `CSV` formats for `Splunk` and `Tableau` integration, respectively.

## Technologies ✨
* Python
* Splunk
* JSON
* Tableau

## Features 🚀
* Extracts `IPs` and `Domains`: Parses pcap files to extract `IP addresses` and `domain names`.

* VirusTotal Query: Cross-references extracted `IoCs` with VirusTotal to determine malicious activity and reputation scores.

* Yara File Scanning: Scans files using Yara rules to detect potential threats.

* Results Export: Saves analysis results in `JSON format` for `Splunk` and `CSV format` for `Tableau` visualization.
