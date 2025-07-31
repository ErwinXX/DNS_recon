import whois
import dns.resolver
import shodan
import requests
import argparse
import socket

argparse =argparse.ArgumentParser(description="this is a basic information gathering tool .",usage="python3 recon.py -d DOMAIN [-s IP]")
argparse.add_argument("-d","--domain" , help ="Enter then name of domain to gather information from" )
argparse.add_argument("-s","--shodan",help="Enter the ip for shodan search")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan
try:
    print("[+] whois info ")
    py = whois.whois(domain)
    print("name:{}".format(py.domain_name))
    #for key, value in py.items():
    #    print(f"{key}: {value}")
except Exception as e:
    print(e)


#dns module
for x in ["A", "NS", "MX", "TXT"]:
    try:
        for a in dns.resolver.resolve(domain, x):
            print("[+] {} Record: {}".format(x, a.to_text()))
    except Exception as e:
        print(f"[-] {x} Record not found: {e}")

