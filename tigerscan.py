#!/usr/bin/env python3
import argparse
import whois
import dns.resolver
import requests
import json
import socket
from typing import Dict, List, Union, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

# Initialize rich console
console = Console()

# ------------------------- CONSTANTS -------------------------
VERSION = "1.0"
AUTHOR = "Faisal Khan (Khansaab)"
BANNER = r"""
  _______ _________ _____  ______ _____   _____ _____  
 |__   __|__   __/ ____|/  ____|  __ \ / ____|  __ \ 
    | |     | | | (___ |  (___ | |__) | |    | |__) |
    | |     | |  \___ \ \___  \|  ___/| |    |  _  / 
    | |     | |  ____) |____)  | |    | |____| | \ \ 
    |_|     |_| |_____/|_____/ |_|     \_____|_|  \_\ 
    Faisal Khan (Khansaab)'S DOMAIN HUNTING WEAPON - v{VERSION}
""".format(VERSION=VERSION)

# ------------------------- UTILITIES -------------------------
def print_banner():
    """Display the tool banner"""
    console.print(Panel.fit(BANNER, style="bold green"))

def error_handler(func):
    """Decorator for error handling in scan modules"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            console.print(f"[red]Error in {func.__name__}:[/red] {str(e)}")
            return None
    return wrapper

def save_results(results: Dict[str, Any], filename: str) -> None:
    """Save scan results to JSON file"""
    try:
        # Ensure filename ends with .json
        if not filename.lower().endswith('.json'):
            filename += '.json'
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4, default=str)  # Added default=str to handle datetime objects
        console.print(f"[green]✓ Results saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to save results: {str(e)}[/red]")

def display_help() -> None:
    """Display comprehensive help information"""
    help_text = f"""
    TIGERSCAN v{VERSION} 🐅 - Advanced Domain Reconnaissance Tool
    
    USAGE:
      python tigerscan.py -d DOMAIN [OPTIONS]
    
    REQUIRED ARGUMENT:
      -d, --domain DOMAIN   Target domain to scan (e.g., example.com)
    
    SCAN OPTIONS:
      --whois               Perform WHOIS lookup
      --dns                 Fetch DNS records (A, MX, NS, TXT, etc.)
      --sub                 Enumerate subdomains using crt.sh
      --ports               Scan common ports (80, 443, 22, etc.)
      --tech                Detect web technologies
      --all                 Run all available scans
    
    OUTPUT OPTIONS:
      --output FILE.json    Save results to JSON file
    
    EXAMPLES:
      1. Basic domain scan:
         python tigerscan.py -d example.com --whois --dns
      
      2. Full scan with output:
         python tigerscan.py -d example.com --all --output results.json
    """
    console.print(Panel.fit(Markdown(help_text), style="bold blue"))
    sys.exit(0)

# ------------------------- SCAN MODULES -------------------------
@error_handler
def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup for a domain"""
    w = whois.whois(domain)
    
    table = Table(title=f"WHOIS Information for {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value", style="green")
    
    for key, value in w.items():
        if value:
            if isinstance(value, list):
                value = "\n".join(str(v) for v in value if v is not None)
            elif value is None:
                continue
            table.add_row(key.upper(), str(value))
    
    console.print(table)
    return dict(w)

@error_handler
def dns_lookup(domain: str) -> Dict[str, List[str]]:
    """Perform DNS record lookup for a domain"""
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    results: Dict[str, List[str]] = {}
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [rdata.to_text() for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue
    
    table = Table(title=f"DNS Records for {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Record Type", style="dim", width=10)
    table.add_column("Values", style="green")
    
    for record, values in results.items():
        table.add_row(record, "\n".join(values))
    
    console.print(table)
    return results

@error_handler
def subdomain_enum(domain: str) -> List[str]:
    """Enumerate subdomains using certificate transparency logs"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Handle case where crt.sh returns an empty array or invalid response
        if not isinstance(data, list):
            console.print("[yellow]No subdomains found or invalid response from crt.sh[/yellow]")
            return []
            
        subdomains = sorted({entry['name_value'].lower().strip() for entry in data 
                            if isinstance(entry, dict) and 'name_value' in entry 
                            and '*' not in entry['name_value']})
        
        if not subdomains:
            console.print("[yellow]No subdomains found[/yellow]")
            return []
        
        table = Table(title=f"Subdomains Found for {domain}", show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("Subdomain", style="green")
        
        for i, sub in enumerate(subdomains, 1):
            table.add_row(str(i), sub)
        
        console.print(table)
        return subdomains
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Subdomain enumeration failed: {str(e)}[/red]")
        return []
    except json.JSONDecodeError:
        console.print("[red]Failed to decode response from crt.sh[/red]")
        return []

@error_handler
def port_scan(domain: str, ports: List[int] = [80, 443, 22, 21, 3306]) -> Dict[str, Union[List[int], str]]:
    """Scan common ports on a domain"""
    try:
        ip = socket.gethostbyname(domain)
        open_ports = []
        
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        
        table = Table(title=f"Port Scan Results for {domain} ({ip})", show_header=True, header_style="bold magenta")
        table.add_column("Port", style="dim")
        table.add_column("Service", style="dim")
        table.add_column("Status", style="green")
        
        port_services = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL"
        }
        
        for port in ports:
            service = port_services.get(port, "Unknown")
            status = "OPEN" if port in open_ports else "CLOSED"
            style = "green" if status == "OPEN" else "dim"
            table.add_row(str(port), service, f"[{style}]{status}[/{style}]")
        
        console.print(table)
        return {'ip': ip, 'open_ports': open_ports}
    except socket.gaierror:
        console.print("[red]Failed to resolve domain to IP address[/red]")
        return {'error': 'Failed to resolve domain'}
    except Exception as e:
        console.print(f"[red]Port scan failed: {str(e)}[/red]")
        return {'error': str(e)}

@error_handler
def tech_detection(domain: str) -> Dict[str, Any]:
    """Detect web technologies used by a domain"""
    schemes = ['https://', 'http://']
    detected_tech: Dict[str, Any] = {}
    
    for scheme in schemes:
        url = f"{scheme}{domain}"
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            response.raise_for_status()
            
            detected_tech = {
                'Final URL': response.url,
                'Status Code': response.status_code,
                'Server': response.headers.get('Server', 'Not detected'),
                'X-Powered-By': response.headers.get('X-Powered-By', 'Not detected'),
                'Security Headers': {
                    'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Not present'),
                    'X-Frame-Options': response.headers.get('X-Frame-Options', 'Not present'),
                    'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Not present'),
                    'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Not present')
                },
                'HTTPS': response.url.startswith('https'),
                'Cookies': [cookie.name for cookie in response.cookies]
            }
            break
        except requests.exceptions.RequestException:
            continue
    
    if not detected_tech:
        console.print("[red]Failed to detect technologies (site might be down)[/red]")
        return {}
    
    table = Table(title=f"Technology Detection for {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Technology", style="dim", width=25)
    table.add_column("Value", style="green")
    
    for key, value in detected_tech.items():
        if isinstance(value, dict):
            table.add_row(key, "\n".join(f"{k}: {v}" for k, v in value.items()))
        elif isinstance(value, list):
            table.add_row(key, "\n".join(value) if value else "None")
        else:
            table.add_row(key, str(value))
    
    console.print(table)
    return detected_tech

# ------------------------- MAIN FUNCTION -------------------------
def main():
    """Main function to handle command-line arguments and execute scans"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description=f"TIGERSCAN v{VERSION} - Advanced Domain Reconnaissance Tool",
        add_help=False
    )
    
    # Required arguments
    parser.add_argument('-d', '--domain', help='Target domain to scan (e.g. example.com)')
    
    # Scan options
    parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    parser.add_argument('--dns', action='store_true', help='Perform DNS record lookup')
    parser.add_argument('--sub', action='store_true', help='Find subdomains via crt.sh')
    parser.add_argument('--ports', action='store_true', help='Scan common ports')
    parser.add_argument('--tech', action='store_true', help='Detect web technologies')
    parser.add_argument('--all', action='store_true', help='Run all available scans')
    
    # Output options
    parser.add_argument('--output', help='Save results to JSON file')
    
    # Help options
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit')
    
    args = parser.parse_args()
    
    if args.help or not any(vars(args).values()):
        display_help()
    
    if not args.domain:
        console.print("[red]Error: Domain is required (use -d/--domain)[/red]")
        display_help()
        sys.exit(1)
    
    results: Dict[str, Any] = {}
    
    if args.all:
        args.whois = args.dns = args.sub = args.ports = args.tech = True
    
    console.print(f"[bold]Starting scan for:[/bold] [green]{args.domain}[/green]\n")
    
    # Execute selected scans
    if args.whois:
        results['whois'] = whois_lookup(args.domain)
    if args.dns:
        results['dns'] = dns_lookup(args.domain)
    if args.sub:
        results['subdomains'] = subdomain_enum(args.domain)
    if args.ports:
        results['ports'] = port_scan(args.domain)
    if args.tech:
        results['tech'] = tech_detection(args.domain)
    
    # Save results if output file specified
    if args.output and results:
        save_results(results, args.output)
    
    console.print(f"\n[bold green]✓ Scan completed for {args.domain}[/bold green]")

if __name__ == '__main__':
    import sys
    main()