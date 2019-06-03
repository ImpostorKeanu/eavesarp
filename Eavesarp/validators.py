#!/usr/bin/env python3

from re import match,compile
from scapy.all import ARP

# Regexp to validate ipv4 structure
ipv4_re = compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

def validate_ipv4(val):
    '''Verify if a given value matches the pattern of an
    IPv4 address.
    '''

    m = match(ipv4_re,val)
    if m: return m
    else: return False

def validate_packet(packet,unpack=True):
    '''Validate a packet to be of type ARP. Leave unpack to True and
    the returned object will be ARP instead of Boolean.
    '''

    if ARP in packet:
        arp = packet.getlayer('ARP')
        if arp.op == 1:
            if unpack: return arp
            else: return True

    return False
