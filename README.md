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

# Example Output

We can see from the following output that `172.16.122.95` is a popular host. Wonder what services it has running? Something cleartext? SMB? Spoof a sender and find out!

*Note*: Blank fields in the *sender* column indicate that the target has been requested by the most recent sender, for example: the first reference to target `172.16.122.81` in the output below was requested by sender `172.16.122.59`.


```
Sender            Target            Count
-----------------------------------------
172.16.122.61     172.16.122.93     1 
172.16.122.101    172.16.122.95     134
172.16.122.22     172.16.122.49     24
172.16.122.59     172.16.122.1      2 
                  172.16.122.81     1 
172.16.122.81     172.16.122.59     1 
                  172.16.122.19     1 
                  172.16.122.106    1 
                  172.16.122.87     1 
                  172.16.122.60     1 
                  172.16.122.67     1 
                  172.16.122.107    1 
                  172.16.122.43     1 
172.16.122.17     172.16.122.1      1 
                  172.16.122.93     1 
172.16.122.94     172.16.122.95     11
172.16.122.103    172.16.122.95     3 
                  172.16.122.93     1 
172.16.122.93     172.16.122.41     1 
                  172.16.122.95     6 
172.16.122.86     172.16.122.1      1 
172.16.122.252    172.16.122.32     4 
172.16.122.57     172.16.122.93     1 
172.16.122.36     172.16.122.104    1 
                  172.16.122.93     1 
172.16.122.37     172.16.122.104    2 
172.16.122.85     172.16.122.1      1 
172.16.122.87     172.16.122.81     1 
                  172.16.122.86     1 
172.16.122.60     172.16.122.81     1 
172.16.122.88     172.16.122.1      1 
172.16.122.104    172.16.122.95     2 
172.16.122.105    172.16.122.93     1 
```

# Usage

Though there are a few more options, `eavesarp.py` can be started by simply: `python3.7 eavesarp.py`. The most interesting options are likely `-ss` and `-ts`, which allow the user to filter requests for desirable IP addresses.

Use the `--help` flag for more information:

```
usage: Analyze ARP requests all eaves-like [-h]
                                           [--interfaces INTERFACES [INTERFACES ...]]
                                           [--redraw-frequency REDRAW_FREQUENCY]
                                           [--pcap-output-file PCAP_OUTPUT_FILE]
                                           [--analysis-output-file ANALYSIS_OUTPUT_FILE]
                                           [--sender-addresses SENDER_ADDRESSES [SENDER_ADDRESSES ...]]
                                           [--target-addresses TARGET_ADDRESSES [TARGET_ADDRESSES ...]]

optional arguments:
  -h, --help            show this help message and exit
  --interfaces INTERFACES [INTERFACES ...], -i INTERFACES [INTERFACES ...]
                        Interfaces to sniff from.
  --redraw-frequency REDRAW_FREQUENCY, -rf REDRAW_FREQUENCY
                        Redraw the screen after each N packets are sniffed
                        from the interface.
  --pcap-output-file PCAP_OUTPUT_FILE, -pof PCAP_OUTPUT_FILE
                        Name of file to dump captured packets
  --analysis-output-file ANALYSIS_OUTPUT_FILE, -aof ANALYSIS_OUTPUT_FILE
                        Name of file to receive analysis output.
  --sender-addresses SENDER_ADDRESSES [SENDER_ADDRESSES ...], -ss SENDER_ADDRESSES [SENDER_ADDRESSES ...]
                        Capture and analyze requests only when the sender
                        address is in the argument supplied to this parameter.
                        Input is a space delimited series of IP addresses.
  --target-addresses TARGET_ADDRESSES [TARGET_ADDRESSES ...], -ts TARGET_ADDRESSES [TARGET_ADDRESSES ...]
                        Capture requests only when the target IP address is in
                        the argument supplied to this parameter. Input is a
                        space delimited series of IP addresses.
```
