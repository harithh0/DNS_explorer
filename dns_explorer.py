import dns
import dns.resolver

res = dns.resolver.Resolver()
res.nameservers = ["8.8.8.8"]
res.port = 53

dns_result = res.resolve("google.com")
for i in dns_result:
    print(str(i))
