## About
- This tool recursively maps out a domain's common subdomains, their IP addresses, and associated reverse DNS (PTR) records. It builds a tree-like structure showing relationships between domains and their resolved hosts.

Example workflow
```yaml
Start: example.com
   |
   | (Forward DNS)
   v
IPs: 192.0.2.1, 198.51.100.5

Reverse lookup of 192.0.2.1:
   PTR -> hostA.example.net

Reverse lookup of 198.51.100.5:
   PTR -> hostB.example.org

Now forward lookup on hostA.example.net:
   IPs: 192.0.2.1, 192.0.2.2

Reverse lookup of 192.0.2.2:
   PTR -> extra.example.com

Forward lookup on extra.example.com:
   IPs: 203.0.113.7

Reverse lookup of 203.0.113.7:
   PTR -> hostC.example.net

...and so on.
```


## Usage

- Add subdomains to `dns_search.txt`, one per line.
- Set your base domain in the script (domain = "example.com").
- Run the script to generate the domain resolution tree.
