import socket
from time import sleep

import dns
import dns.resolver

res = dns.resolver.Resolver()
res.nameservers = ["8.8.8.8"]
res.port = 53

domain = "uca.edu"
domains_and_results = {}

with open("offensive_dns_exploration/dns_search.txt", "r") as f:
    sub_domains = f.read().splitlines()

# for i in dns_result:
#     print(socket.gethostbyaddr(i.to_text())[0])


def reverseDnsLookup(address: str) -> str:
    """Returns hostname from IP address"""

    # NOTE: can return alias aswell @ [1]
    ptr_record = socket.gethostbyaddr(address)
    return ptr_record[0]


def dnsRequest(domain: str):
    try:
        dns_result = res.resolve(domain)
        addresses_for_domain = [addr.to_text() for addr in dns_result]
        print(f"{domain} {addresses_for_domain}")
        for address in addresses_for_domain:
            try:
                rev_results = reverseDnsLookup(address)
                print(rev_results)
            except Exception as e:
                print("no PTR record found for address:", address)
                rev_results = []

            print(f"sub for {address} -> {rev_results}")
            if domain in domains_and_results:
                domains_and_results[domain].append({address: rev_results})
            else:
                domains_and_results[domain] = [{address: rev_results}]
    except Exception as e:
        print(str(e))
        pass
        # print(f"{domain} couldn't find")


for sub_domain in sub_domains:
    created_req = f"{sub_domain}.{domain}"
    dnsRequest(created_req)
print("-" * 100)
print(domains_and_results)
