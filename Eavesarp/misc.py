#!/usr/bin/env python3

import netifaces

def unpack_arp(arp):
    '''Validate a packet while returning the target and sender
    in a tuple: `(target,sender)`
    '''

    return arp.psrc,arp.hwsrc,arp.pdst

def unpack_packet(packet):
    '''Extract and return the ARP layer from a packet object.
    '''

    return unpack_arp(packet.getlayer('ARP'))

def get_interfaces(require_ip=False):
    interfaces = {}
    for iface in netifaces.interfaces():

        if iface == 'lo': continue

        addrs = netifaces.ifaddresses(iface)

        try: ips = [a['addr'] for a in addrs[2]]
        except: ips = []

        try: hwaddr = [a['addr'] for a in addrs[17]][0]
        except: hwaddr = ''

        if require_ip and not ips: continue

        interfaces[iface] = (hwaddr,ips,)

    return interfaces
