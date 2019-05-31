#!/usr/bin/env python3

from .sql import *
from .lists import Lists

import re
from scapy.all import sniff,ARP,wrpcap,rdpcap,sr
from pathlib import Path
from time import sleep
from os import remove
from tabulate import tabulate
from multiprocessing.pool import Pool
from dns import reversename, resolver

# TODO: To make this more like an API, move printing/coloring/output structuring
# to the interface section

def validate_file_presence(func):
    '''Determine if a file is found on the local filesystem.
    '''

    def wrapper(fname,*args,**kwargs):

        p = Path(fname)
        if p.exists() and p.is_file():
            return func(fname,*args,**kwargs)
        else:
            raise Exception(
                f'File not found: {fname}'
            )

    return wrapper


def validate_packet_unpack(func):
    '''Validate a packet to be ARP and return the
    ARP layer.
    '''

    def wrapper(packet,*args,**kwargs):

        arp = validate_packet(packet)

        if not arp:
            return False
        else:
            return func(unpack_arp(arp), *args, **kwargs)
        

    return wrapper


def unpack_packets(func):
    '''Unpack a list of packets to src/dst addresses.
    '''
    
    def wrapper(packets, *args, **kwargs):

        packets = [unpack_packet(packet) for packet in packets]

        return func(packets, *args, **kwargs)

    return wrapper

# =========
# FUNCTIONS
# =========

def arp_request(interface,target,verbose=0,retry=0,timeout=1):
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

def unpack_arp(arp):
    '''Validate a packet while returning the target and sender
    in a tuple: `(target,sender)`
    '''

    return arp.psrc,arp.hwsrc,arp.pdst

def unpack_packet(packet):
    '''Extract and return the ARP layer from a packet object.
    '''

    return unpack_arp(packet.getlayer('ARP'))

def get_transactions(db_session,order_by=desc):

    # Getting all transaction objects
    return db_session.query(Transaction) \
            .order_by(desc(Transaction.count)) \
            .all()

def create_db(dbfile,overwrite=False):
    '''Initialize the database file and return a session
    object.
    '''

    engine = create_engine(f'sqlite:///{dbfile}')
    Session = sessionmaker()
    Session.configure(bind=engine)

    pth = Path(dbfile)

    # Remove the file if specified
    if pth.exists() and overwrite:
        remove(pth)

    # Don't clobber pre-existing database files
    if not Path(dbfile).exists() or overwrite:
        Base.metadata.create_all(engine)

    return Session()

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

@validate_packet_unpack
def filter_packet(packet,sender_lists=None,target_lists=None):
    '''Filter an individual packet. This should be executed in the `lambda`
    supplied to `do_sniff`. `sender_lists` and `target_lists` should be 
    objects of type `List()`.
    '''

    if not packet: return False
    sender,shw,target = packet

    if sender_lists:
        if not sender_lists.check(sender):
            return False
    if target_lists:
        if not target_lists.check(target):
            return False

    return packet

def get_or_create_ip(ip, db_session, reverse_resolve=False, ptr=None,
        interface=None, arp_resolve=False, mac=None):
    '''Get or create an IP object from the SQLite database. Also
    handles:

    - Reverse Name Resolution
    - ARP resolution
    '''

    db_ip = db_session.query(IP).filter(IP.value==ip).first()

    if not db_ip:

        ip = IP(value=ip,mac_address=mac)

        if mac: ip.arp_resolve_attempted = True

        db_session.add(ip)
        db_session.commit()

        # Obtain and set the PTR record for a given IP
        if ptr:

            db_session.add(
                PTR(ip_id=ip.id,value=ptr)
            )
            db_session.commit()

        # Attempt to resolve the PTR address
        elif reverse_resolve:

            ptr,forward_ip = reverse_dns_resolve(ip.value)

            if ptr:

                db_session.add(
                    PTR(ip_id=ip.id,
                        value=ptr,
                        forward_ip=forward_ip)
                )
                db_session.commit()

            ip.reverse_dns_attempted = True

        # Handle ARP request if active is enabled
        if arp_resolve and not ip.arp_resolve_attempted:

            hwaddr = arp_request(interface,
                ip.value)
            if hwaddr: ip.mac_address = hwaddr
            ip.arp_resolve_attempted = True
            db_session.commit()


    else:
        
        ip = db_ip

        if reverse_resolve and not ip.reverse_dns_attempted:

            ptr,forward_ip = reverse_dns_resolve(ip.value)

            if ptr:

                db_session.add(
                    PTR(ip_id=ip.id,
                        value=ptr,
                        forward_ip=forward_ip)
                )

            ip.reverse_dns_attempted = True
            db_session.commit()

        if arp_resolve and not db_ip.mac_address and not ip.arp_resolve_attempted:

            hwaddr = arp_request(interface,
                ip.value)
            if hwaddr: ip.mac_address = hwaddr
            ip.arp_resolve_attempted = True

            db_session.commit()

    return ip

@unpack_packets
def handle_packets(packets,db_session,reverse_resolve=False,
        arp_resolve=False,interface=None):
    '''Handle packets capture from the interface.
    '''

    if arp_resolve:

        if not interface:
            raise Exception(
                'Active ARP resolution requires an interface ip'
            )

    for packet in packets:

        sender,shw,target = packet

        # GET/CREATE database objects
        sender = get_or_create_ip(sender,
                db_session,
                reverse_resolve,
                mac=shw)

        target = get_or_create_ip(target,
                db_session,
                reverse_resolve,
                arp_resolve=arp_resolve,
                interface=interface)

        # Determine if a transaction record for the 
          # target/sender pair exists
            # if not, create it
            # else, get and increment it
        transaction = db_session.query(Transaction) \
            .filter(
                Transaction.sender_ip_id==sender.id,
                Transaction.target_ip_id==target.id
            ).first()

        if not transaction:

            transaction = Transaction(sender_ip_id=sender.id,
                    target_ip_id=target.id)
            db_session.add(transaction)

        else:

            transaction.count += 1
        
        # Populate stale field in transaction when appropriate
        if not target.mac_address and target.arp_resolve_attempted:
            transaction.stale_target = True


        db_session.commit()

def do_sniff(interfaces,redraw_frequency,sender_lists,target_lists):
    '''Start the sniffer while filtering for WHO-HAS broadcast requests.
    '''

    return sniff(iface=interfaces,
        lfilter=lambda pkt: filter_packet(pkt,sender_lists,target_lists),
        count=redraw_frequency
    )
   
def async_sniff(interface, redraw_frequency, sender_lists,
        target_lists, dbfile, analysis_output_file=None, reverse_resolve=False, 
        color_profile=None, verbose=False, arp_resolve=False):
    '''This function should be started in a distinct process, allowing
    the one to CTRL^C during execution and gracefully exit the sniffer.
    Not starting the sniffer in a distinct process results in it blocking
    forever or until an inordinate number of keyboard interrupts occur.
    '''

    sess = create_db(dbfile)

    # Capture packets
    packets = do_sniff(interface,
            redraw_frequency, sender_lists,
            target_lists)

    # Handle packets (to the db they go, yo)
    handle_packets(packets,
            sess,
            reverse_resolve,
            arp_resolve,
            interface,
    )

    return packets

def analyze(database_output_file, sender_lists=None, target_lists=None,
        analysis_output_file=None, pcap_files=[], sqlite_files=[],
        color_profile=None, reverse_resolve=True, *args, **kwargs):
    '''Create a new database and populate it with records stored in
    each type of input file.
    '''

    outdb_sess = create_db(database_output_file,overwrite=True)

    # ===================
    # HANDLE SQLITE FILES
    # ===================

    '''
    Import the source database to the new database by reading in
    each transaction. Note that new id values are assigned to
    each IP in the process.
    '''
    for sfile in sqlite_files:
        
        isess = create_db(sfile)

        # ====================================================
        # ITERATE OVER EACH TRANSACTION AND TRANSFER TO NEW DB
        # ====================================================

        for t in isess.query(Transaction).all():

            # ===============
            # HANDLE POINTERS
            # ===============

            if t.sender.ptr: sptr = t.sender.ptr[0].value
            else: sptr=None

            if t.target.ptr: tptr = t.target.ptr[0].value
            else: tptr=None

            # =================
            # HANDLE IP OBJECTS
            # =================

            sender = get_or_create_ip(t.sender.value,outdb_sess,ptr=sptr,mac=t.sender.mac_address)
            target = get_or_create_ip(t.target.value,outdb_sess,ptr=tptr,mac=t.target.mac_address)

            # ======================
            # HANDLE THE TRANSACTION
            # ======================

            transaction = outdb_sess.query(Transaction).filter(
                Transaction.sender_ip_id==sender.id,
                Transaction.target_ip_id==target.id).first()

            if transaction:

                transaction.count += t.count

            else:

                outdb_sess.add(
                    Transaction(
                        sender_ip_id=sender.id,
                        target_ip_id=target.id,
                        count=t.count,
                        stale_target=t.stale_target
                    )
                )

            outdb_sess.commit()

    # =====================
    # HANDLE EACH PCAP FILE
    # =====================

    '''
    This is much easier than SQLITE files since we can just use
    Scapy to slurp the packets from each target file, filter each
    packet, and then use `handle_packets` to populate the database.
    '''

    for pfile in pcap_files:

        # Assure that each packet is ARP WHO-HAS
        packets = [p for p in rdpcap(pfile) if filter_packet(p)]

        # Insert the records
        handle_packets(
            packets,
            outdb_sess
        )

    return get_output(
            outdb_sess,
            sender_lists=sender_lists,
            target_lists=target_lists,
            color_profile=color_profile,
            reverse_resolve=reverse_resolve)

