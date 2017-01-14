DNS helper
==========
Helper functions for building DNS requests and parsing DNS responses, DNS cache and test program.

Example using the DNS server 8.8.8.8:53:
```
./testdns 8.8.8.8:53
dns> help
Commands:
  help: shows this help.

  resolve <QCLASS> <name>: resolves <name>
          <QCLASS> ::= "A" | "CNAME" | "MX" | "AAAA" | "SOA"

  quit: quits the program.


dns> resolve a www.google.com
Id: 0x4567
Questions:
  Question:
    Name: 'www.google.com'
    Type: A (1)
    Class: IN (0x0001)

Answers:
  Resource record:
    Name: 'www.google.com'
    Type: A (1)
    Class: IN (0x0001)
    Time to live: 299
    Data length: 4
    IPv4: 172.217.23.164

Add to DNS cache (Y/N)? y
Added 'www.google.com' -> 172.217.23.164 to DNS cache.
dns> resolve a www.google.com
(From cache) IPv4: 172.217.23.164
dns> resolve a www.yahoo.com
Id: 0x23c6
Questions:
  Question:
    Name: 'www.yahoo.com'
    Type: A (1)
    Class: IN (0x0001)

Answers:
  Resource record:
    Name: 'www.yahoo.com'
    Type: CNAME (5)
    Class: IN (0x0001)
    Time to live: 142
    Data length: 15
    CNAME: 'fd-fp3.wg1.b.yahoo.com'

  Resource record:
    Name: 'fd-fp3.wg1.b.yahoo.com'
    Type: A (1)
    Class: IN (0x0001)
    Time to live: 14
    Data length: 4
    IPv4: 46.228.47.115

  Resource record:
    Name: 'fd-fp3.wg1.b.yahoo.com'
    Type: A (1)
    Class: IN (0x0001)
    Time to live: 14
    Data length: 4
    IPv4: 46.228.47.114

Add to DNS cache (Y/N)? y
Added 'www.yahoo.com' -> 46.228.47.115 to DNS cache.
dns> resolve a www.yahoo.com
(From cache) IPv4: 46.228.47.115
dns> quit
```

The DNS parser recognizes the following classes:
  * A
  * CNAME
  * MX
  * AAAA
  * SOA
