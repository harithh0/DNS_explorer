import os
import socket
import sys
from time import sleep
from typing import Union

import dns
import dns.resolver
from loguru import logger

# remove the default logger
logger.remove()

logger.add(
    sink=sys.stderr,
    format=
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}",
)

res = dns.resolver.Resolver()
res.nameservers = ["127.0.0.1"]
res.port = 8053

domain = "example.com"
domains_and_results = {}
script_dir = os.path.dirname(__file__)
sub_domain_file_name = "sub_domains.txt"
with open(os.path.join(script_dir, sub_domain_file_name), "r") as f:
    sub_domains = f.read().splitlines()


def build_dns_tree(data):
    from collections import defaultdict

    # Build reverse tree: parent → [children]
    tree = defaultdict(list)
    roots = []

    for domain, info in data.items():
        parent = info["PARENT_DOMAIN"]
        if parent is None:
            roots.append(domain)
        else:
            tree[parent].append(domain)

    def print_tree(node, prefix=""):
        ips = ", ".join(data[node]["IPS"])
        print(f"{prefix}{node} ({ips})")
        children = tree.get(node, [])
        for i, child in enumerate(children):
            is_last = i == len(children) - 1
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "
            print_tree(child, prefix + connector)

    for root in roots:
        print_tree(root)


def reverseDnsLookup(address: str) -> str:
    """Returns hostname from IP address"""
    # INFO:
    # May not result in the same hostname as a regular DNS query

    # INFO: can return alias aswell @ [1]
    ptr_record = socket.gethostbyaddr(address)
    return ptr_record[0]


def dnsRequest(domain: str, main_domain: Union[str | None] = None) -> None:
    present = False
    if domain in domains_and_results:
        present = True
    try:
        dns_result = res.resolve(domain)

    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        # INFO: The domain does not exist at all in DNS. (That domain never existed)
        # The authoritative name servers confirmed that the domain isn’t in the zone file

        # domains[domain] = "Does not exist"
        return
    except dns.resolver.NoAnswer:
        # INFO: The domain exists, but there is no DNS record of the type you asked for (e.g., A, AAAA, etc.)
        # The DNS resolver successfully contacted the authoritative server, but got an empty response

        # domains[domain] = "Exist's but no DNS record of type"
        return

    addresses_for_domain = list(set([addr.to_text() for addr in dns_result]))
    logger.debug(f"{domain} {addresses_for_domain}")

    # for each address find that address's, hostname
    for address in addresses_for_domain:
        try:
            rev_results = reverseDnsLookup(address)
        except Exception as e:
            # ptr record couldn't be found for this domain
            continue
        logger.debug(f"sub for {address} -> {rev_results}")

        if present:
            total_ips = list(
                set(domains_and_results[domain].get("IPS") +
                    addresses_for_domain))
            domains_and_results[domain]["IPS"] = total_ips
        else:
            domains_and_results[domain] = {
                "IPS": list(set(addresses_for_domain)),
                "PARENT_DOMAIN": main_domain,
            }
            dnsRequest(rev_results, main_domain=domain)


for sub_domain in sub_domains:
    created_req = f"{sub_domain}.{domain}"
    dnsRequest(created_req)

    # test common host name extensions like www1 www2 ns1 ns2 etc...
    for i in range(0, 10):
        num_req = f"{sub_domain}{i}.{domain}"
        dnsRequest(num_req)

# print("-" * 100)
# print(domains_and_results)
# print("-" * 100)
build_dns_tree(domains_and_results)
