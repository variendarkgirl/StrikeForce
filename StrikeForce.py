from tabulate import tabulate
import argparse
import dns.resolver
import requests
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from tqdm import tqdm
import time
from collections import defaultdict  # Added this line to fix the NameError
  
# Initialize colorama
init(autoreset=True)


COMMON_PORTS = [21, 22, 23, 80, 443, 8080, 8443]
MAX_WORKERS = 100
REQUEST_TIMEOUT = 10

def print_banner():
    banner = f"""{Fore.CYAN}
    ███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗███╗   ███╗
    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║████╗ ████║
    ███████╗██║   ██║██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║██║██╔████╔██║
    ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╔╝██║
    ███████║╚██████╔╝██║     ███████╗██████╔╝███████╗██║ ╚████║██║██║ ╚═╝ ██║
    ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝
    {Style.RESET_ALL}
    {Fore.RED}Strike Force v3.0{Style.RESET_ALL}
    {Fore.YELLOW}Ultimate Subdomain Enumeration Tool{Style.RESET_ALL}
    """
    print(banner)

# Core enumeration functions
def certificate_transparency(domain):
    """Query crt.sh for certificate logs"""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry['name_value'].lower().strip()
                if '*' in name: continue
                if domain in name and name not in [domain, f'*.{domain}']:
                    subs.add(name)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching Certificate Transparency data: {e}{Style.RESET_ALL}")
    return subs

def dns_dumpster(domain):
    """Scrape DNS Dumpster"""
    subs = set()
    try:
        session = requests.Session()
        resp = session.get('https://dnsdumpster.com/', timeout=REQUEST_TIMEOUT)
        csrf_match = re.search(r"csrfmiddlewaretoken.*?value='(.*?)'", resp.text)
        if not csrf_match:
            print(f"{Fore.RED}[!] Error scraping DNS Dumpster: CSRF token not found{Style.RESET_ALL}")
            return subs
        csrf = csrf_match.group(1)
        headers = {'Referer': 'https://dnsdumpster.com/', 'Cookie': f'csrftoken={csrf}'}
        data = {'csrfmiddlewaretoken': csrf, 'targetip': domain}
        resp = session.post('https://dnsdumpster.com/', data=data, headers=headers)
        matches = re.findall(rf"[\w.-]+\.{re.escape(domain)}", resp.text, re.I)
        subs.update([m.lower() for m in matches if m != domain])
    except Exception as e:
        print(f"{Fore.RED}[!] Error scraping DNS Dumpster: {e}{Style.RESET_ALL}")
    return subs

def wayback_machine(domain):
    """Query Wayback Machine"""
    subs = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:  # Skip header row
                for entry in data[1:]:
                    match = re.search(rf"(https?://)?([\w.-]+\.{re.escape(domain)})", entry[2], re.I)
                    if match: subs.add(match.group(2).lower())
    except Exception as e:
        print(f"{Fore.RED}[!] Error querying Wayback Machine: {e}{Style.RESET_ALL}")
    return subs

def hackertarget(domain):
    """Query HackerTarget API"""
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                parts = line.split(',')
                if len(parts) > 1 and domain in parts[0]:
                    subs.add(parts[0].lower())
    except Exception as e:
        print(f"{Fore.RED}[!] Error querying HackerTarget: {e}{Style.RESET_ALL}")
    return subs

def resolve_dns(subdomains):
    """Batch DNS resolution with caching"""
    resolved = defaultdict(list)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    
    def resolve_single(sub):
        try:
            answers = resolver.resolve(sub, 'A')
            return (sub, [str(r) for r in answers])
        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving {sub}: {e}{Style.RESET_ALL}")
            return (sub, [])
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(resolve_single, sub): sub for sub in subdomains}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving DNS", ncols=80):
            sub, ips = future.result()
            if ips:
                resolved[sub] = ips
    
    return resolved

def port_scan(ip, ports):
    """Efficient port scanner"""
    open_ports = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        for port in ports:
            try:
                if s.connect_ex((ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append(f"{port}/{service}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error scanning port {port} on {ip}: {e}{Style.RESET_ALL}")
    return ", ".join(open_ports) if open_ports else "None"

def sublist3r_style(domain):
    """Comprehensive enumeration combining multiple sources"""
    sources = [
        certificate_transparency,
        dns_dumpster,
        wayback_machine,
        hackertarget
    ]
    
    all_subs = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(source, domain): source.__name__ for source in sources}
        for future in as_completed(futures):
            source_name = futures[future]
            try:
                subs = future.result()
                print(f"{Fore.GREEN}[+] Found {len(subs)} subdomains from {source_name}{Style.RESET_ALL}")
                all_subs.update(subs)
            except Exception as e:
                print(f"{Fore.RED}[!] Error from {source_name}: {e}{Style.RESET_ALL}")
    return all_subs

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Ultimate Subdomain Scanner')
    parser.add_argument('domain', help='Target domain (e.g. example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to subdomain wordlist')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=COMMON_PORTS,
                      help=f'Ports to scan (default: {COMMON_PORTS})')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-open-ports', action='store_true', help='Scan for open ports on discovered IPs')
    args = parser.parse_args()
    print(f"{Fore.YELLOW}[+] Starting comprehensive scan for {args.domain}{Style.RESET_ALL}")
    
    # Phase 1: Passive Enumeration
    print(f"{Fore.CYAN}[+] Passive Enumeration Phase{Style.RESET_ALL}")
    passive_subs = sublist3r_style(args.domain)
    
    # Display all passive subdomains
    if passive_subs:
        print(f"{Fore.GREEN}[+] Passive Subdomains Found:{Style.RESET_ALL}")
        for sub in sorted(passive_subs):
            print(f"  {Fore.BLUE}{sub}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No passive subdomains found{Style.RESET_ALL}")
    
    # Phase 2: Active Brute-force
    brute_subs = set()
    if args.wordlist:
        print(f"{Fore.CYAN}[+] Active Brute-force Phase{Style.RESET_ALL}")
        try:
            with open(args.wordlist) as f:
                words = [line.strip() for line in f if line.strip()]
            
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(dns.resolver.resolve, f"{word}.{args.domain}", 'A'): word for word in words}
                for future in tqdm(as_completed(futures), total=len(futures), desc="Brute-forcing", ncols=80):
                    word = futures[future]
                    try:
                        future.result()
                        brute_subs.add(f"{word}.{args.domain}")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error brute-forcing {word}.{args.domain}: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Brute-force error: {e}{Style.RESET_ALL}")
    
    # Combine results
    all_subs = passive_subs.union(brute_subs)
    print(f"{Fore.GREEN}[+] Found {len(all_subs)} unique subdomains{Style.RESET_ALL}")
    
    # Display all combined subdomains
    if all_subs:
        print(f"{Fore.GREEN}[+] All Combined Subdomains Found:{Style.RESET_ALL}")
        for sub in sorted(all_subs):
            print(f"  {Fore.BLUE}{sub}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No subdomains found{Style.RESET_ALL}")
    
    # DNS Resolution
    resolved = resolve_dns(all_subs)
    
    # Port Scanning
    if args.open_ports:
        print(f"{Fore.CYAN}[+] Port Scanning Phase{Style.RESET_ALL}")
        results = []
        total_ips = sum(len(ips) for ips in resolved.values())
        with tqdm(total=total_ips, desc="Port Scanning", ncols=80) as pbar:
            for sub, ips in resolved.items():
                for ip in ips:
                    ports = port_scan(ip, args.ports)
                    results.append([sub, ip, ports])
                    pbar.update(1)
    else:
        results = [[sub, ip, "N/A"] for sub, ips in resolved.items() for ip in ips]
    
    # Filter out unresolved subdomains from results
    filtered_results = [row for row in results if row[1] != "N/A"]
    
    # Display Results
    print(f"\n{Fore.YELLOW}[+] Final Results:{Style.RESET_ALL}")
    if filtered_results:
        print(tabulate(filtered_results, 
                     headers=[f"{Fore.GREEN}Subdomain", f"{Fore.BLUE}IP Address", f"{Fore.MAGENTA}Open Ports"],
                     tablefmt="grid"))
    else:
        print(f"{Fore.RED}[!] No resolved subdomains found{Style.RESET_ALL}")
    
    # Save Output
    if args.output:
        with open(args.output, 'w') as f:
            for row in filtered_results:
                f.write(f"{row[0]}\t{row[1]}\t{row[2]}\n")
        print(f"{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
