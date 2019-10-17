#!/usr/bin/env python3

import signal
import re
from Eavesarp.sql import *
from Eavesarp.lists import Lists
from Eavesarp.decorators import *
from Eavesarp.validators import *
from Eavesarp.resolve import *
from Eavesarp.misc import *
from Eavesarp.output import *
from Eavesarp.logo import *
from scapy.all import sniff,ARP,wrpcap,rdpcap,sr
from time import sleep
from multiprocessing.pool import Pool
from sys import stdout


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
        color_profile=None, dns_resolve=True, csv_output_file=None,
        output_columns=None, stale_only=False, force_sender=False,
        *args, **kwargs):
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

    print(get_output_table(
        outdb_sess,
        sender_lists=sender_lists,
        target_lists=target_lists,
        color_profile=color_profile,
        columns=output_columns,
        stale_only=stale_only,
        force_sender=force_sender
    ))

    if csv_output_file:
        print(f'- Writing csv output to {csv_output_file}')
        with open(csv_output_file,'w') as outfile:
            outfile.write(
                get_output_csv(
                    outdb_sess,
                    sender_lists=sender_lists,
                    target_lists=target_lists
                ).read()
            )

    outdb_sess.close()

def capture(interface,database_output_file,redraw_frequency,arp_resolve,
        dns_resolve,sender_lists,target_lists,color_profile,
        output_columns,display_false,pcap_output_file,force_sender,
        stale_only,*args,**kwargs):

    dbfile = database_output_file

    osigint = signal.signal(signal.SIGINT,signal.SIG_IGN)
    pool = Pool(3)
    signal.signal(signal.SIGINT, osigint)

    try:

        # ==============
        # START SNIFFING
        # ==============

        '''
        The sniffer is started in a distinct process because Scapy
        will block forever when scapy.all.sniff is called. This allows
        us to interrupt execution of the sniffer by terminating the
        process.

        TODO: It may be easier to use threading. Pool methods were fresh
        to me at the time of original development.
        '''


        ptable = None
        pcount = 0
        # Handle new database file. When verbose, alert user that a new
        # capture must occur prior to printing results.

        arp_resolution = ('disabled','enabled')[arp_resolve]
        dns_resolution = ('disabled','enabled')[dns_resolve]

        print('\x1b[2J\x1b[H\33[F')
        print(logo+'\n')
        print(f'Capture interface: {interface}')
        print(f'ARP resolution:    {arp_resolution}')
        print(f'DNS resolution:    {dns_resolution}')
        sess = create_db(dbfile)

        # ======================================
        # CREATE AN IP FOR THE CURRENT INTERFACE
        # ======================================


        iface_mac, iface_ips = get_interfaces()[interface]
        for ip in iface_ips:
            ip = get_or_create_ip(ip,
                sess,
                mac_address=iface_mac)

        if not Path(dbfile).exists():
            print('- Initializing capture\n- This may take time depending '\
                'on network traffic and filter configurations')
        else:

            print(f'Requests analyzed: {pcount}\n')
            ptable = get_output_table(
                sess,
                sender_lists=sender_lists,
                target_lists=target_lists,
                dns_resolve=dns_resolve,
                color_profile=color_profile,
                arp_resolve=arp_resolve,
                columns=output_columns,
                display_false=display_false,
                force_sender=force_sender,
                stale_only=stale_only)
            print(ptable)

        # Cache packets that will be written to output file
        pkts = []
        sniff_result = None
        arp_resolve_result, dns_resolve_result = None, None

        # Loop eternally
        while True:


            # Handle sniff results
            if sniff_result and sniff_result.ready():

                packets = sniff_result.get()
                sniff_result = None

                # Capture packets for the output file
                if pcap_output_file and packets: pkts += packets

                if packets: pcount += packets.__len__()

                # Clear the previous table from the screen using
                # escape sequences screen
                # https://stackoverflow.com/questions/5290994/remove-and-replace-printed-items/5291044#5291044
                if ptable:
                    lcount = ptable.split('\n').__len__()+2
                    stdout.write('\033[F\033[K'*lcount)

                ptable = get_output_table(
                    sess,
                    sender_lists=sender_lists,
                    target_lists=target_lists,
                    dns_resolve=dns_resolve,
                    color_profile=color_profile,
                    arp_resolve=arp_resolve,
                    columns=output_columns,
                    display_false=display_false,
                    force_sender=force_sender,
                    stale_only=stale_only)

                print(f'Requests analyzed: {pcount}\n')
                print(ptable)

            # Do sniffing
            elif not sniff_result:


                sniff_result = pool.apply_async(
                    async_sniff,
                    (
                        interface,
                        redraw_frequency,
                        sender_lists,
                        target_lists,
                        database_output_file,
                    )
                )

            # ==================
            # DNS/ARP RESOLUTION
            # ==================

            # Do reverse resolution
            if dns_resolve:

                # Reset dns resolution results
                if not dns_resolve_result or dns_resolve_result.ready():

                    to_resolve = sess.query(IP) \
                            .filter(IP.reverse_dns_attempted != True) \
                            .count()

                    if to_resolve:

                       dns_resolve_result = pool.apply_async(
                            reverse_dns_resolve_ips,
                            (database_output_file,)
                        )

            # Do ARP resolution
            if arp_resolve:

                if not arp_resolve_result or arp_resolve_result.ready():

                    to_resolve = sess.query(IP) \
                            .filter(IP.arp_resolve_attempted != True) \
                            .count()

                    if to_resolve:

                        arp_resolve_result = pool.apply_async(
                            arp_resolve_ips,
                                (interface, database_output_file,)
                            )

            sleep(.2)


    except KeyboardInterrupt:

        print('\n- CTRL^C Caught...')
        sess.close()

    finally:

        # ===================
        # HANDLE OUTPUT FILES
        # ===================

        if pcap_output_file: wrpcap(pcap_output_file,pkts)

        # =====================
        # CLOSE CHILD PROCESSES
        # =====================

        try:

            pool.close()

            if sniff_result:
                print('- Waiting for the sniffer process...',end='')
                sniff_result.wait(5)
                print('done')

            if dns_resolve_result:
                print('- Waiting for the DNS resolver process...',end='')
                dns_resolve_result.wait(5)
                print('done')

            if arp_resolve_result:
                print('- Waiting for the ARP resolver ocess...',end='')
                arp_resolve_result.wait(5)
                print('done')

        except KeyboardInterrupt:

            pool.terminate()

        pool.join()

