#!/usr/bin/env python3

from Eavesarp.sql import *
from Eavesarp.lists import Lists
from Eavesarp.decorators import *
from Eavesarp.validators import *
from Eavesarp.resolve import *
from Eavesarp.misc import *

import re
from scapy.all import sniff,ARP,wrpcap,rdpcap,sr
from time import sleep
from tabulate import tabulate
from multiprocessing.pool import Pool

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

@unpack_packets
def handle_packets(packets,db_session):
    '''Handle packets capture from the interface.
    '''

    for packet in packets:

        sender,shw,target = packet

        # GET/CREATE database objects
        sender = get_or_create_ip(sender,
                db_session,
                mac_address=shw)

        target = get_or_create_ip(target,
                db_session)

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

        db_session.commit()

def do_sniff(interfaces,redraw_frequency,sender_lists,target_lists):
    '''Start the sniffer while filtering for WHO-HAS broadcast requests.
    '''

    return sniff(iface=interfaces,
        lfilter=lambda pkt: filter_packet(pkt,sender_lists,target_lists),
        count=redraw_frequency
    )
   
def async_sniff(interface, redraw_frequency, sender_lists,
        target_lists, dbfile):
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
    handle_packets(packets, sess)

    sess.close()

    return packets

def analyze(database_output_file, sender_lists=None, target_lists=None,
        analysis_output_file=None, pcap_files=[], sqlite_files=[],
        color_profile=None, dns_resolve=True, *args, **kwargs):
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

            ips = []
            for handle in ['sender','target']:

                transaction_ip = tip = t.__getattribute__(handle)

                # Create a dictionary of arguments to create the IP
                kwargs = {
                    'db_session':outdb_sess,
                }
                for attr in ['value','arp_resolve_attempted',
                    'reverse_dns_attempted', 'mac_address']:
                    kwargs[attr] = tip.__getattribute__(attr)
               
                # Create the new IP
                ip = get_or_create_ip(**kwargs)

                # Associate the ptr
                ptr = tip.ptr[0].value if tip.ptr else None
                if ptr:

                    get_or_create_ptr(ptr,ip.id,outdb_sess,
                            tip.ptr[0].forward_ip)

                # Append the ip
                ips.append(ip)

            # Expand list into sender/target value
            sender, target = ips

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

    outdb_sess.close()
