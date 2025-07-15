"""
Honeypot DNS Resolver for redirecting unavailable domains to honey IP addresses
"""

import sys
import time

from dnslib import *
from dnslib.server import DNSServer
from loguru import logger

host = "localhost"
port = 8053

logger.remove()
logger.add(sys.stderr, format="{time:HH:mm} {level} {message}", level="INFO")

# INFO:
"""
If we own a specific IP block like 219.20.120.0/24 and a main domain, we can make it where we have our valid subdomains on valid IP addresses that point to them, and
honey subdomains that point to an IP address that can be running a honey pot service that looks legit.

Real world approach:
- Use DNS provider for legit domain names
- Use Honey Resolver for illegitimate hostnames, by forwarding DNS queries to the Honey domains to the Honey Resolver via your DNS provider:
    trap.example.com    NS    → ns1.trap.example.com
    ns1.trap.example.com A    → YOUR_PUBLIC_IP
    - The resolver then directly queries ns1.trap.example.com (where the Honey Resolver will be running) if the user does a DNS request to trap.example.com
"""

domain = "example.com"
subdomains = {
    "www.": {
        "A": "219.20.120.1",
        "AAAA": "2401:fa00:dead:beef:abcd:1234:5678:90ab"
    },
    "api.": {
        "A": "219.20.120.3",
        "AAAA": "2001:0db8:3a5f:1c2d:9a3b:00ff:fe21:5d4b"
    },
}

honeydomains = {
    "smtp.": {
        "A": "219.20.120.22",
        "AAAA": "2401:fa00:dead:beef:abcd:1234:5678:abcd"
    },
    "vpn.": {
        "A": "219.20.120.21",
        "AAAA": "2001:0db8:3a5f:1c2d:9a3b:00ff:fe21:1234"
    },
}

domain_record = {
    "A": "219.20.120.1",
    "AAAA": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}

default_honey_record = {
    "A": "219.20.120.23",
    "AAAA": "2401:fa00:dead:beef:1234:5678:9abc:def0",
}
supported_queries = ("A", "AAAA")


class HoneyResolver:

    def build_answer(self, reply_obj, data, query_type, qtype):
        query_type_obj = RDMAP[query_type]
        reply_obj.add_answer(
            RR(
                rname=reply_obj.q.qname,
                rtype=qtype,
                rclass=1,
                ttl=300,
                rdata=query_type_obj(data),
            ))

    def resolve(self, request, handler):
        # Receives DNSRecord object
        subdomain = str(request.q.qname.stripSuffix(domain + "."))
        qtype = request.q.qtype
        query_type = QTYPE.get(request.q.qtype)
        reply = request.reply()

        # validates if we support that query type and if we get a invalid query type (is None)
        if query_type not in supported_queries or query_type is None:
            # indicating that we don't support this query (NOANSWER)
            reply.header.rcode = RCODE.NOERROR
            return reply

        # Builds reply specific to the request (template DNS response based on the incoming request)
        if subdomain != ".":
            if subdomain in subdomains:
                ip = subdomains[subdomain].get(query_type)
                self.build_answer(reply, ip, query_type, qtype)
            elif subdomain in honeydomains:
                honey_ip = honeydomains[subdomain].get(query_type)
                self.build_answer(reply, honey_ip, query_type, qtype)
            else:
                # return default honey IP
                # self.build_answer(reply, default_honey_record)

                # return NXDOMAIN (domain does not exist)
                reply.header.rcode = RCODE.NXDOMAIN
        else:
            # no subdomain provided
            self.build_answer(reply, domain_record.get(query_type), query_type,
                              qtype)
        return reply


if __name__ == "__main__":
    resolver = HoneyResolver()
    server = DNSServer(resolver, port=port, address=host)

    try:
        logger.info("Starting DNS server...")
        server.start()
    except KeyboardInterrupt:
        logger.info("Stopping DNS server...")
        server.stop()
