---
title: "DNS Tunneling"
classes: wide
header:
  teaser: /assets/images/Blogs/dns_tunneling/logo.jpg
ribbon: green
description: "Exploits the DNS protocol to bypass security controls, enabling data exfiltration, C2 communication."
categories:
 - Blog
toc: true
---

## **What is DNS Tunneling?**

The Domain Name System (DNS) is a crucial protocol that translates domain names (e.g., google.com) into IP addresses. Because DNS is allowed in most networks even those protected by firewalls and proxies attackers exploit it as a covert channel to exfiltrate data, communicate with compromised machines, or execute remote commands.

This technique is known as DNS Tunneling, where malware hides malicious traffic inside legitimate-looking DNS queries and responses, making detection difficult. So attacks have been used to great effect by malicious actors in the real world, leading to significant damage to industries and organizations.

## How Does DNS Tunneling Work?

#### The Core Concept

DNS Tunneling works by embedding encoded data inside DNS requests and responses, allowing attackers to bypass security controls.

![](/assets\images\Blogs\dns_tunneling\core_concept.png)

#### Typical Steps in a DNS Tunneling Attack:

1. A compromised machine sends a DNS query containing encoded data to an attacker-controlled domain.

2. The attacker’s DNS server decodes the query and processes the request.

3. The attacker responds with a DNS reply containing encoded data, which the malware on the infected device deciphers.

4. This communication loop continues, allowing data exfiltration or command execution without triggering traditional security alerts.

## How Attackers Execute DNS Tunneling

- ##### Setting Up the Attack an attacker needs:

  - A domain name under their control (e.g., attackerdomain.com).
  - A custom DNS server to handle tunneling.
  - A malware implant on the victim’s machine.

1. ##### Encoding Data Inside DNS Queries instead of sending data directly, attackers encode it inside DNS queries.

   - Example of a normal DNS request: `google.com`
   - Example of a DNS request used for tunneling: `aGVsbG8gd29ybGQ.attackerdomain.com`
   - Here, `aGVsbG8gd29ybGQ` is Base64-encoded data that translates to “Hello World.” 
   - The attacker’s server decodes it and extracts the hidden message.

2. ##### Receiving the Data on the Attacker’s Server the attacker’s DNS server extracts the encoded data, processes it, and sends a response containing additional encoded instructions back to the infected machine.

3. ##### Using DNS Tunneling as a Command-and-Control (C2) Channel that DNS Tunneling isn’t just for data exfiltration, it’s also used for remote control.


A compromised machine might send this query: `cm0gLXN0cmYgL2hvbWUvdXNlci9wYXNzd2Q=.attackerdomain.com` Which translates to: `rm -strf /home/user/password`

This allows an attacker to execute system commands through DNS, completely bypassing traditional security tools.

## DNS Types

##### **1. A (Address Record)**

Purpose: Returns the IPv4 address of a domain.

Example Query: `example.com → A`

Example Response:

```
example.com → 192.168.1.1
```

------

##### **2. AAAA (IPv6 Address Record)**

 Purpose: Returns the IPv6 address of a domain.

Example Query: `example.com → AAAA`

Example Response: 

```
example.com → 2001:db8::1
```

------

##### **3. CNAME (Canonical Name Record)**

 Purpose: Creates an alias for another domain name.

 Example Query: `www.example.com → CNAME`

Example Response: 

```
www.example.com → example.com
```

------

##### **4. MX (Mail Exchange Record)**

 Purpose: Specifies the mail server for a domain.

 Example Query: `example.com → MX`

Example Response: 

```
mail.example.com (Priority: 10)
```

------

##### **5. TXT (Text Record)**

 Purpose: Stores text information, often used for email authentication (SPF, DKIM, DMARC).

 Example Query: `example.com → TXT`

Example Response: 

```
"v=spf1 include:_spf.google.com ~all"
```

------

##### **6. NS (Name Server Record)**

 Purpose: Specifies the authoritative name servers for a domain.

 Example Query: `example.com → NS`

 Example Response:

```
ns1.example.com
ns2.example.com
```

------

##### **7. SOA (Start of Authority Record)**

 Purpose: Provides administrative details about a domain zone.

 Example Query: `example.com → SOA`

Example Response:

```
Primary Name Server: ns1.example.com
Admin Email: admin@example.com
Serial: 2024022401
```

------

##### **8. PTR (Pointer Record)**

 Purpose: Used for reverse DNS lookups (IP to domain name).

 Example Query: `192.168.1.1 → PTR`

Example Response:

```
example.com
```

------

##### **9. SRV (Service Record)**

 Purpose: Defines the location (port and hostname) of specific services.

 Example Query: `_service._proto.example.com → SRV`

Example Response:

```
Priority: 10
Weight: 5
Port: 5060
Target: sip.example.com
```

------

##### **10. NAPTR (Naming Authority Pointer Record)**

 Purpose: Used for rewriting rules in VoIP and SIP services.

 Example Query: `example.com → NAPTR`

Example Response:

```
Order: 100
Preference: 10
Flags: "s"
Service: "SIP+D2U"
Regexp: "!^.*!sip:server.example.com!"
Replacement: .
```

## RogueroBin Malware

**RogueRobin** is a sophisticated trojan attributed to the **DarkHydrus** (APT) group, first identified in 2016. This malware is notable for its advanced evasion techniques and versatile command-and-control (C2) communication methods.

#### Command-and-Control Communication

- **DNS Tunneling**: The malware encodes data within DNS queries, allowing it to communicate with its C2 server covertly. It tests various DNS query types (TXT, MX, A, and AAAA) to determine the most effective method in the target environment. 

- **Google Drive API**: In later variants, RogueRobin incorporates the use of the Google Drive API as an alternative C2 channel. It uploads and monitors files on a Google Drive account controlled by the attackers, enabling them to send commands and receive data through a legitimate cloud service, thereby blending malicious traffic with normal network activity.

![](/assets\images\Blogs\dns_tunneling\c2_conn.png)

The following [link](https://n1ght-w0lf.github.io/malware%20analysis/roguerobin-trojan/#c2-communications) provides details on the communication methods used by **RogueRobin** to establish a Command and Control (C2) channels.

## Detecting DNS Tunneling Using Splunk

**SIEM query** that detects suspicious DNS activity based on **TXT, MX, A, and AAAA** queries that used in **RogueroBin** as example. It identifies excessive requests from a single source, which could indicate **DNS tunneling or C2 communication**.

```
index=dns_logs  
| stats count by src_ip, query_type, domain
| where query_type IN ("TXT", "MX", "A", "AAAA")
| where count > 50
| table _time, src_ip, query_type, domain, count
| sort - count
```

## Detecting DNS Tunneling With Suricata

Suricata rules are **signature-based detection rules** used in **Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), and Network Security Monitoring**. These rules define patterns and conditions to detect **malicious traffic**, including exploits, malware, and data exfiltration.

And here is the rule that detects our malware:

```
alert dns any any -> any any (msg:"Possible DNS Tunneling - Excessive Queries"; 
sid:100001; rev:1; priority:1;
threshold: type both, track by_src, count 50, seconds 60; 
classtype:network-protocol-command-decode;)
```

## How to block!

1. #### Restrict External DNS Servers

   - Force all devices to use a **trusted DNS server** (e.g., **Cloudflare (1.1.1.1), Google (8.8.8.8), or OpenDNS**).

   - Block all outbound DNS traffic to **unauthorized DNS servers** using a firewall.

2. #### Block or Rate-Limit DNS TXT Records

   - Many DNS tunneling techniques **hide data inside TXT records**.

   - You can **limit or block DNS TXT requests** unless necessary for business operations.

3. #### Use DNS Filtering Solutions

   Implement **DNS Security tools** like: `Cisco Umbrella` or `Cloudflare Gateway`.

## Final Thoughts

DNS Tunneling remains a significant threat due to its ability to bypass traditional security controls by exploiting a widely allowed protocol. Attackers leverage it for data exfiltration, remote command execution, and maintaining stealthy C2 channels, making it a favored technique among APT groups and cybercriminals.

For SOC analysts, detecting and mitigating DNS Tunneling is crucial. By implementing robust monitoring strategies, leveraging SIEM solutions, and enforcing strict DNS security policies, organizations can minimize the risks associated with this attack vector. A proactive approach to DNS security is essential to safeguarding networks from covert threats.
