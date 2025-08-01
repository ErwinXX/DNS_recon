import argparse
import socket
import dns.resolver
import requests
import shodan
import whois
import os
import sys
from colorama import Fore, Style, init

init(autoreset=True)
socket.setdefaulttimeout(2)

def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def print_success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def whois_lookup(domain):
    print_info("Performing WHOIS lookup...")
    try:
        w = whois.whois(domain)
        print_success(f"Domain Name: {w.domain_name}")
        print_success(f"Registrar: {w.registrar}")
        print_success(f"Creation Date: {w.creation_date}")
        print_success(f"Expiration Date: {w.expiration_date}")
        print_success(f"Name Servers: {w.name_servers}")
        print_success(f"Emails: {w.emails}")
    except Exception as e:
        print_error(f"WHOIS lookup failed: {e}")

def check_dns_records(domain):
    print_info("Checking DNS records...")
    for record in ["A", "NS", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            for answer in answers:
                print_success(f"{record} Record: {answer.to_text()}")
        except Exception as e:
            print_error(f"{record} Record not found: {e}")

def subdomain_enum(domain, wordlist="subdomains.txt"):
    print_info("Enumerating subdomains...")
    try:
        with open(wordlist, "r") as f:
            for line in f:
                sub = f"{line.strip()}.{domain}"
                try:
                    ip = socket.gethostbyname(sub)
                    print_success(f"{sub} -> {ip}")
                except:
                    pass
    except FileNotFoundError:
        print_error(f"Wordlist {wordlist} not found!")

def reverse_dns(ip):
    print_info("Performing reverse DNS lookup...")
    try:
        hostname = socket.gethostbyaddr(ip)
        print_success(f"Reverse DNS: {hostname[0]}")
    except:
        print_error("Reverse DNS failed.")

def shodan_lookup(ip):
    print_info("Querying Shodan...")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        print_error("Set SHODAN_API_KEY environment variable!")
        return
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        print_success(f"IP: {result['ip_str']}")
        print_success(f"Org: {result.get('org', 'N/A')}")
        print_success(f"OS: {result.get('os', 'N/A')}")
        for service in result['data']:
            print_success(f"Port: {service['port']}")
            print(service['data'])
    except Exception as e:
        print_error(f"Shodan lookup failed: {e}")

def banner_grab(ip):
    print_info("Grabbing banners...")
    common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080]
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode().strip()
            print_success(f"{ip}:{port} Banner: {banner}")
            s.close()
        except:
            continue

def main():
    parser = argparse.ArgumentParser(
        description="ReconCTF - A Reconnaissance Tool for CTFs",
        usage="python3 script.py -d DOMAIN [-s IP] [-w WORDLIST]"
    )
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-s", "--shodan", help="Target IP for Shodan & Banner Grab")
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist", default="subdomains.txt")

    args = parser.parse_args()

    if not args.domain and not args.shodan:
        parser.print_help()
        sys.exit(1)

    if args.domain:
        whois_lookup(args.domain)
        subdomain_enum(args.domain, args.wordlist)
        check_dns_records(args.domain)

    if args.shodan:
        banner_grab(args.shodan)
        shodan_lookup(args.shodan)
        reverse_dns(args.shodan)

if __name__ == "__main__":
    main()
