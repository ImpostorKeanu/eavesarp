#!/usr/bin/env python3
from Eavesarp.sql import *
from scapy.all import ARP,sr
from dns import reversename, resolver

def reverse_dns_resolve(ip):
    '''Attempt reverse name resolution on an IP address. Returns
    `None` upon exception, which occurs when an address without a
    PTR record is requested.
    '''
    
    try:

        rev_name = reversename.from_address(ip)
        r = resolver.query(rev_name,'PTR')[0].__str__()
        
        # Do forward lookup of reverse name since the new IP
        # may differ
        try:
            f = resolver.query(r)[0].__str__()
        except:
            f = None

        return r,f        

    except:

        return None,None

def reverse_dns_resolve_ips(db_file):

    sess = create_db(db_file)
    ips = sess.query(IP) \
        .filter(IP.reverse_dns_attempted != True) \
        .all()

    for ip in ips:
        ptr,forward_ip = reverse_dns_resolve(ip.value)
        if ptr:
            sess.add(
                PTR(ip_id=ip.id,
                    value=ptr[:ptr.__len__()-1],
                    forward_ip=forward_ip)
                )
        ip.reverse_dns_attempted = True
        sess.commit()

    sess.close()

def arp_resolve(interface,target,verbose=0,retry=0,timeout=1):
    '''Attempt to make an ARP request for the target. Returns
    the MAC address for the target if successful, None otherwise.
    '''

    results, unanswered = sr(
        ARP(
            op=1,
            pdst=target,
        ),
        iface=interface,
        retry=retry,
        verbose=verbose,
        timeout=timeout
    )

    if results:
        return results[0][1].hwsrc
    else:
        return None

def arp_resolve_ips(interface,db_file,verbose=0,retry=0,timeout=1):

    sess = create_db(db_file)
    to_resolve = sess.query(IP) \
                    .filter(IP.arp_resolve_attempted != True) \
                    .all()

    for ip in to_resolve:

        hwaddr = arp_resolve(interface,ip.value,verbose,retry,timeout)

        if hwaddr:
            ip.mac_address = hwaddr

        ip.arp_resolve_attempted = True
        sess.commit()

    sess.close()

    return None
