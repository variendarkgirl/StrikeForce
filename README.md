# Strike Force v3.0 - Advanced Subdomain Enumeration Tool  

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)  

## Overview  

**Strike Force v3.0** is a powerful subdomain enumeration tool built for penetration testers and security researchers. It uses multiple data sources to discover subdomains, perform DNS brute-forcing, and optionally scan open ports. This tool is perfect for uncovering hidden infrastructure and mapping attack surfaces.  

---  

## Features  

- **Comprehensive Subdomain Enumeration**:  
  Aggregates results from multiple sources like Certificate Transparency logs, DNS Dumpster, Wayback Machine, and HackerTarget.  
- **DNS Brute-Forcing**: Use custom wordlists to find additional subdomains.  
- **Port Scanning**: Identify open ports on discovered subdomains.  
- **Progress Tracking**: Includes progress bars to monitor task execution.  
- **Detailed Results**: Save results to a file for further analysis.  

---  

## Installation  

1. Clone the repository:  
   ```bash  
   git clone https://github.com/yourusername/strike-force.git  
   cd strike-force  
   ```  

2. Install required dependencies:  
   ```bash  
   pip install -r requirements.txt  
   ```  

---  

## Usage  

Run the tool with the target domain as an argument:  

```bash  
python3 subdomain_enumerator.py example.com  
```  

### Key Arguments  

- **Domain** (Required): Specify the target domain (e.g., `example.com`).  
- **Wordlist**: Use a custom wordlist for DNS brute-forcing.  
  ```bash  
  -w /path/to/wordlist.txt  
  ```  
- **Custom Ports**: Define ports for scanning.  
  ```bash  
  -p 80 443 8080  
  ```  
- **Save Results**: Save output to a file.  
  ```bash  
  -o results.txt  
  ```  
- **Port Scanning**: Enable scanning for open ports.  
  ```bash  
  -open-ports  
  ```  

#### Full Example:  
```bash  
python3 subdomain_enumerator.py example.com -w wordlist.txt -p 22 80 443 -o results.txt -open-ports  
```  

---  

## Configuration  

Customizable settings within the script:  
- **`COMMON_PORTS`**: Default ports to scan.  
- **`MAX_WORKERS`**: Number of threads for concurrency.  
- **`REQUEST_TIMEOUT`**: Timeout for network requests.  

---  

## Data Sources  

The tool gathers subdomains from:  
1. **Certificate Transparency Logs**: Queries `crt.sh`.  
2. **DNS Dumpster**: Scrapes `dnsdumpster.com`.  
3. **Wayback Machine**: Extracts URLs from the Internet Archive.  
4. **HackerTarget**: Fetches subdomains via API.  
5. **Brute-Force**: Finds subdomains using a wordlist.  

---  

## Example Output  

```plaintext  
Strike Force v3.0 - Advanced Subdomain Enumeration  

[+] Starting enumeration for example.com  
[+] Passive Enumeration Phase:  
    - Found 10 subdomains from Certificate Transparency Logs  
    - Found 4 subdomains from HackerTarget  
[+] Active Enumeration Phase:  
    - Brute-forcing DNS with wordlist.txt: 50% complete...  
[+] Scanning Open Ports:  
    - Open ports discovered on 5 subdomains  
[+] Results:  
+-----------------------+--------------+------------+  
| Subdomain             | IP Address   | Open Ports |  
+-----------------------+--------------+------------+  
| www.example.com       | 192.168.1.1  | 80, 443    |  
| mail.example.com      | 192.168.1.2  | 25, 587    |  
+-----------------------+--------------+------------+  
[+] Results saved to results.txt  
```  

---  

## Special Thanks  

A special thank you to ([Striker OP](https://github.com/str1k3r0p)) for his invaluable contributions and continuous support in the development of this tool.

---  
## Contributing  

We welcome contributions! Follow these steps to contribute:  
1. Fork the repository.  
2. Create a branch: `git checkout -b feature-name`.  
3. Commit changes: `git commit -m "Add feature"`.  
4. Push your branch: `git push origin feature-name`.  
5. Open a pull request.  

---  

## License  

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  

---  

## Contact  

For questions or support, contact us at **strikerop@example.com** or open an issue on GitHub.  

---  

**Disclaimer**: Ensure you have permission before scanning any domain. Follow the terms of service for each data source used in this tool.  

---
