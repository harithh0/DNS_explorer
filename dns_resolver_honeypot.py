"""
Honeypot DNS Resolver for redirecting unavailable domains to honey IP addresses
"""

import sys

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
"""

domain = "example.com"
subdomains = {"www.": "219.20.120.1", "api.": "219.20.120.3"}
domain_ip = "219.20.120.1"

honeydomains = {"smtp.": "219.20.120.22", "vpn.": "219.20.120.21"}
defualt_honey_ip = "219.20.120.23"


class HoneyResolver:

    def build_answer(self, reply_obj, data):
        reply_obj.add_answer(
            RR(
                rname=reply_obj.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=300,
                rdata=A(data),
            ))

    def resolve(self, request, handler):
        # Receives DNSRecord object
        subdomain = str(request.q.qname.stripSuffix(domain + "."))

        # Builds reply specific to the request (template DNS response based on the incoming request)
        reply = request.reply()
        if subdomain != ".":
            if subdomain in subdomains:
                ip = subdomains[subdomain]
                self.build_answer(reply, ip)
            elif subdomain in honeydomains:
                honey_ip = honeydomains[subdomain]
                self.build_answer(reply, honey_ip)
            else:
                # return default honey IP
                # self.build_answer(reply, defualt_honey_ip)

                # return NXDOMAIN (domain does not exist)
                reply.header.rcode = RCODE.NXDOMAIN
        else:
            # no subdomain provided
            self.build_answer(reply, domain_ip)
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
