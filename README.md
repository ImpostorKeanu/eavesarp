# Eavesarp

A reconnaissance tool that analyzes ARP requests to identify hosts that are likely communicating with one another, which is useful in those dreaded situations where LLMNR/NBNS aren't in use for name resolution.

**Brought to you by:**

![Black Hills Information Security](https://www.blackhillsinfosec.com/wp-content/uploads/2016/03/BHIS-logo-L-300x300.png "Black Hills Information Security")

## Requirements/Installation

`eavesarp` requires Python3.7 and Scapy. After installing Python, run the following to install Scapy: `python3.7 -m pip install -r requirements.txt`

# How it do?

Using Scapy, `eavesarp` simply:

0. Listens for broadcasted ARP requests
0. Tracks number of times each host resolves the MAC for a given IP
0. Dumps the counts to stdout
