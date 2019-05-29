#!/usr/bin/env python3

import re
import colored
from scapy.all import sniff,ARP,wrpcap,rdpcap,sr
from pathlib import Path
from time import sleep
from os import remove
from tabulate import tabulate
from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey,
        func, text, ForeignKeyConstraint, UniqueConstraint,
        create_engine, asc, desc, Boolean)
from sqlalchemy.orm import (relationship, backref, sessionmaker,
        close_all_sessions)
from sqlalchemy.ext.declarative import declarative_base
from multiprocessing.pool import Pool
from dns import reversename, resolver
from emoji import emojize
import socket
import fcntl
import struct

from sys import exit

# TODO: To make this more like an API, move printing/coloring/output structuring
# to the interface section

class ColorProfile:

    def __init__(self,even_color,odd_color,header_color,
            header_bold=True,target_emoji=None):

        self.even_style = colored.fg(even_color)
        self.odd_style = colored.fg(odd_color)

        self.header_style = colored.fg(header_color)
        if header_bold: self.header_style += colored.attr('bold')

        self.target_emoji=target_emoji

    def style_header(self,headers):
        return self.style_list(headers,self.header_style)

    def style_even(self,values):
        return self.style_list(values,self.even_style)

    def style_odd(self,values):
        return self.style_list(values,self.odd_style)

    def style_list(self, values, style):
        return [colored.stylize(v,style) for v in values]

ColorProfiles = {
    'disable':None,
    # Practical color profiles
    'default':ColorProfile(even_color=254, odd_color=244,
            header_color=254, header_bold=True),
    '1337':ColorProfile(even_color=28, odd_color=118,
            header_color=28, header_bold=True),
    'agent_orange':ColorProfile(even_color=166, odd_color=179,
            header_color=166, header_bold=True),
    'evil':ColorProfile(even_color=124, odd_color=9,
            header_color=9, header_bold=True),
    'cobalt':ColorProfile(even_color=245, odd_color=26,
            header_color=245, header_bold=True),
    # Novelty color profiles
    'cupcake':ColorProfile(even_color=104, odd_color=164,
        header_color=104, header_bold=True,
        target_emoji=emojize(':unicorn_face:')),
    'poo':ColorProfile(even_color=136, odd_color=94,
            header_color=136, header_bold=True,
            target_emoji=emojize(':pile_of_poo:')),
    'foxhound':ColorProfile(even_color=166, odd_color=179,
            header_color=166, header_bold=True,
            target_emoji=emojize(':fox_face:')),
    'rhino':ColorProfile(even_color=254, odd_color=244,
            header_color=254, header_bold=True,
            target_emoji=emojize(':rhinoceros:'))
}

# =========
# CONSTANTS
# =========

# Regexp to validate ipv4 structure
ipv4_re = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

# =========================
# SQLALCHEMY INITIALIZATION
# =========================

Base = declarative_base()
class IP(Base):
    '''IP model.
    '''

    __tablename__ = 'ip'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False, unique=True,
            doc='IP address value')
    ptr = relationship('PTR', back_populates='ip')
    arp_resolve_attempted = Column(Boolean, nullable=False, default=False,
        doc='''Determines if an ARP request has been made for this host
        ''')
    mac_address = Column(String, nullable=True, unique=True,
        doc='''The MAC address obtained via ARP request.
        ''')
    sender_transactions = relationship('Transaction',
          back_populates='sender',
          primaryjoin='and_(Transaction.sender_ip_id==IP.id)')
    target_transactions = relationship('Transaction',
          back_populates='target',
          primaryjoin='and_(Transaction.target_ip_id==IP.id)')

    def __eq__(self,val):
        '''Override to allow string comparison.
        '''

        if klass == str and self.value == val:
            return True

        super().__eq__(val)

class PTR(Base):
    '''PTR model.
    '''

    __tablename__ = 'ptr'
    id = Column(Integer, primary_key=True)
    ip_id = Column(Integer, ForeignKey(IP.id), nullable=False,unique=True)
    ip = relationship('IP', back_populates='ptr')
    value = Column(String, nullable=False, unique=True,
            doc='PTR value')

class Transaction(Base):
    '''Transaction model.
    '''

    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    sender_ip_id = Column(Integer,nullable=False)
    target_ip_id = Column(Integer,nullable=False)
    count = Column(Integer,default=1)
    sender = relationship('IP',
         back_populates='sender_transactions',
         primaryjoin='and_(Transaction.sender_ip_id==IP.id)')
    target = relationship('IP',
         back_populates='target_transactions',
         primaryjoin='and_(Transaction.target_ip_id==IP.id)')
    ForeignKeyConstraint(
        [sender_ip_id,target_ip_id],
        [IP.id,IP.id],
    )

# ==========
# DECORATORS
# ==========

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

def get_ip_address(ifname):
    '''Get the IP address for a given interface name.
    '''
    # http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', bytes(ifname[:15],'utf-8'))
    )[20:24])

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

@validate_file_presence
def ipv4_from_file(infile):

    addrs = []
    with open(infile) as lines:

        for line in lines:

            line = line.strip()
            if validate_ipv4(line): addrs.append(line)
            else: continue
    
    return addrs

def validate_ipv4(val):
    '''Verify if a given value matches the pattern of an
    IPv4 address.
    '''

    m = re.match(ipv4_re,val)
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

def unpack_arp(arp):
    '''Validate a packet while returning the target and sender
    in a tuple: `(target,sender)`
    '''

    return arp.psrc,arp.pdst

def unpack_packet(packet):
    '''Extract and return the ARP layer from a packet object.
    '''

    return unpack_arp(packet.getlayer('ARP'))

def get_output(db_session,order_by=desc,sender_lists=None,
        target_lists=None,ptr=False,color_profile=None,
        resolve=True,active=False):
    '''Extract transaction records from the database and return
    them formatted as a table.
    '''

    # Getting all transaction objects
    transactions = db_session.query(Transaction) \
            .order_by(desc(Transaction.count)) \
            .all()

    if not transactions:
        output = '- No accepted ARP requests captured\n' \
        '- If this is unexpected, check your whitelist/blacklist configuration'
        return output
    # Organize all the records by sender IP
    rowdict = {}
    for t in transactions:

        # Add a new pair of columns when reverse dns resolution is enabled

#            sender = t.sender.value
#            target = t.target.value
#           
#            if sender_lists and not sender_lists.check(sender):
#                continue
#            if target_lists and not target_lists.check(target):
#                continue
#
#            # Building table rows
#            if sender not in rowdict:
#                # Initialize new sender IP with initial row
#                rowdict[sender] = [[sender,target,t.count,sptr,tptr]]
#            else:
#                # Add new row to known sender IP
#                rowdict[sender].append(['',target,t.count,'',tptr])

        # Simplified output when reverse dns is disabled
            
        sender = t.sender.value
        target = t.target.value

        if sender_lists and not sender_lists.check(sender):
            continue
        if target_lists and not target_lists.check(target):
            continue

        # Flag to determine if the sender is new
        if sender not in rowdict: new_sender = True
        else: new_sender = False

        # Include sender only on new instances
        if new_sender: row = [sender,target]
        else: row = ['',target]

        # Stale IP
        if active:

            sploit_char = ''
            if not t.target.mac_address and t.target.arp_resolve_attempted:

                if color_profile and color_profile.target_emoji:
                    sploit_char = color_profile.target_emoji
                else:
                    sploit_char = 'X'

            row.append(sploit_char)

        # Target count
        row.append(str(t.count))

        # Reverse name resolution
        if resolve:

            sptr = ''
            tptr = ''

            if t.sender.ptr: sptr = t.sender.ptr[0].value
            if t.target.ptr: tptr = t.target.ptr[0].value

            if new_sender: row.append(sptr)
            else: row.append('')

            row.append(tptr)

        if new_sender: rowdict[sender] = [row]
        else: rowdict[sender].append(row)

    # Restructure dictionary into a list of rows
    rows = []
    counter = 0

    for sender,irows in rowdict.items():
        counter += 1

        # Color odd rows slightly darker
        if color_profile:

            if counter % 2:
                rows += [color_profile.style_odd([v for v in r]) for r in irows]
            else:
                rows += [color_profile.style_even(r) for r in irows]

        # Just add the rows otherwise
        else: rows += irows

    # Build the header
    headers = ['Sender','Target','ARP#']
    if active: headers.insert(2,'TS')
    if resolve: headers += ['Sender PTR','Target PTR']

    # Color the headers
    if color_profile: headers = color_profile.style_header(headers)

    # Return the output as a table
    return tabulate(
            rows,
            headers=headers)

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

def reverse_resolve(ip):
    '''Attempt reverse name resolution on an IP address. Returns
    `None` upon exception, which occurs when an address without a
    PTR record is requested.
    '''
    
    try:
        rev_name = reversename.from_address(ip)
        return resolver.query(rev_name,'PTR')[0].__str__()
    except:
        return None

@validate_packet_unpack
def filter_packet(packet,sender_lists=None,target_lists=None):
    '''Filter an individual packet. This should be executed in the `lambda`
    supplied to `do_sniff`. `sender_lists` and `target_lists` should be 
    objects of type `List()`.
    '''

    if not packet: return False
    sender,target = packet

    if sender_lists:
        if not sender_lists.check(sender):
            return False
    if target_lists:
        if not target_lists.check(target):
            return False

    return packet

def get_or_create_ip(ip,db_session,resolve=False,ptr=None):
    '''Get or create an IP object from the SQLite database.
    '''

    db_ip = db_session.query(IP).filter(IP.value==ip).first()

    if not db_ip:

        ip = IP(value=ip)
        db_session.add(ip)
        db_session.commit()

        # Obtain and set the PTR record for a given IP
        if ptr:

            db_session.add(
                PTR(ip_id=ip.id,value=ptr)
            )

            db_session.commit()

        elif resolve:

            ptr = reverse_resolve(ip.value)

            if ptr:

                db_session.add(
                    PTR(ip_id=ip.id,value=ptr)
                )

            db_session.commit()

    else: ip = db_ip

    return ip

@unpack_packets
def handle_packets(packets,db_session,resolve=False,active=False,interface=None):

    if active:

        if not interface:
            raise Exception(
                'Active ARP resolution requires an interface ip'
            )

    for packet in packets:

        sender,target = packet

        # Determine if target/sender IP is in database
          # if not, create it
        sender = get_or_create_ip(packet[0],db_session,resolve)
        target = get_or_create_ip(packet[1],db_session,resolve)

        if active and not target.arp_resolve_attempted:
            hwaddr = arp_request(interface,
                target.value)
            if hwaddr:
                target.mac_address = hwaddr
            target.arp_resolve_attempted = True
            db_session.commit()

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

            transaction = Transaction(sender_ip_id=sender.id, target_ip_id=target.id)
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
        target_lists, dbfile, analysis_output_file=None, resolve=False, 
        color_profile=None, verbose=False, active=False):
    '''This function should be started in a distinct process, allowing
    the one to CTRL^C during execution and gracefully exit the sniffer.
    Not starting the sniffer in a distinct process results in it blocking
    forever or until an inordinate number of keyboard interrupts occur.
    '''

    # Handle new database file. When verbose, alert user that a new
    # capture must occur prior to printing results.
    if not Path(dbfile).exists():

        if verbose: print(
            '- Initializing capture\n- This may take time depending '\
            'on network traffic and filter configurations'
        )
        sess = create_db(dbfile)

    # Dump the existing database to stdout prior to sniffing.
    else:
        
        sess = create_db(dbfile)
        print('\x1b[2J\x1b[H')
        print(
            get_output(
                sess,
                sender_lists=sender_lists,
                target_lists=target_lists,
                resolve=resolve,
                color_profile=color_profile,
                active=active
            )
        )

    # Capture packets
    packets = do_sniff(interface,
            redraw_frequency, sender_lists,
            target_lists)

    # Handle packets (to the db they go, yo)
    handle_packets(packets,
            sess,
            resolve,
            active,
            interface,
    )

    # output,packets
    return get_output(
            sess,
            sender_lists=sender_lists,
            target_lists=target_lists,
            resolve=resolve,
            color_profile=color_profile,
            active=active),packets

def analyze(database_output_file, sender_lists=None, target_lists=None,
        analysis_output_file=None, pcap_files=[], sqlite_files=[],
        color_profile=None, resolve=True, *args, **kwargs):
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

            sender = get_or_create_ip(t.sender.value,outdb_sess,ptr=sptr)
            target = get_or_create_ip(t.target.value,outdb_sess,ptr=tptr)

            # ======================
            # HANDLE THE TRANSACTION
            # ======================

            transaction = outdb_sess.query(Transaction).filter(
                Transaction.sender_ip_id==sender.id,
                Transaction.target_ip_id==target.id).first()

            if transaction:

                it = outdb_sess.query(Transaction).filter(
                    Transaction.sender_ip_id==sender.id,
                    Transaction.target_ip_id==target.id
                ).first()

                it.count += t.count

            else:

                outdb_sess.add(
                    Transaction(
                        sender_ip_id=sender.id,
                        target_ip_id=target.id,
                        count=t.count
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
            resolve=resolve)

class Lists:

    def __init__(self,white=None,black=None):

        self.white = white or []
        self.black = black or []

    def __repr__(self):

        return f'<Lists white:{self.white}, black:{self.black}>'

    def check(self,ip):
        '''Check an IP against a Lists object to determine if it
        should be included in output.
        '''
    
        if self.black and ip in self.black:
            return False
        elif self.white and ip not in self.white:
            return False
        else:
            return True

if __name__ == '__main__':
    
    # ====================================
    # BUSH LEAGUE: Make arguments reusable
    # ====================================

    class Argument:
        '''Basic object that will be used to add arguments
        to argparse objects automagically.
        '''

        def __init__(self, *args, **kwargs):

            self.args = args
            self.kwargs = kwargs

        def add(self, target):
            '''Add the argument to the target argparse object.
            '''

            target.add_argument(*self.args, **self.kwargs)

    whitelist = Argument('--whitelist', '-wl',
        nargs='+',
        help='''Global whitelist. Values supplied to this
        parameter will be added to the whitelist for both
        senders and targets.
        ''')

    blacklist = Argument('--blacklist', '-bl',
        nargs='+',
        help='''Global blacklist. Values supplied to this
        parameter will be added to the blacklist for both
        senders and targets.
        ''')

    sender_whitelist = Argument('--sender-whitelist','-sw',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')

    target_whitelist = Argument('--target-whitelist','-tw',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')
    
    sender_blacklist = Argument('--sender-blacklist','-sb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
    
    target_blacklist = Argument('--target-blacklist','-tb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')

    database_output_file = Argument('--database-output-file','-dof',
        default='eavesarp.db',
        help='''Name of the SQLite database file to output.
        Default: %(default)s
        '''
    )
    
    analysis_output_file = Argument('--analysis-output-file','-aof',
        default='',
        help='''Name of file to receive analysis output.
        '''
    )
    
    # Reverse DNS Configuration
    resolve = Argument('--resolve','-r',
        action='store_true',
        help='''Disable reverse resolution of IP addresses.
        ''')
    
    # Make color optional
    disable_color = Argument('--disable-color','-dc',
        action='store_true',
        help='''Disable colored printing''')

    color_profile = Argument('--color-profile','-cp',
        default='default',
        choices=list(ColorProfiles.keys()),
        help=''''Color profile to use. Set to "disable" to remove color
        altogether.''')

    # =============
    # BUILD THE CLI
    # =============

    import argparse
    main_parser = argparse.ArgumentParser(
        'Analyze ARP requests all eaves-like',
    )
    main_parser.set_defaults(cmd=None)

    subparsers = main_parser.add_subparsers(help='sub-command help',
        metavar='')

    # ============================
    # ANALYZE SUBCOMMAND ARGUMENTS
    # ============================

    analyze_parser = subparsers.add_parser('analyze',
        aliases=['a'],
        help='Analyze an sqlite database or pcap file')
    analyze_parser.set_defaults(cmd='analyze')

    general_group = analyze_parser.add_argument_group(
        'General Configuration Parameters'
    )

    resolve.add(general_group)
    #disable_color.add(general_group)
    color_profile.add(general_group)


    # INPUT FILES
    input_group = analyze_parser.add_argument_group(
        'Input Parameters'
    )
    input_group.add_argument('--pcap-files','-pfs',
        nargs='+',
        default=[],
        help='pcap file to analyze')
    input_group.add_argument('--sqlite-files','-sfs',
        nargs='+',
        default=[],
        help='''SQLite files previously created by eavesarp. Useful
        when aggregating multiple databases.
        ''')

    # OUTPUT FILES
    aog = analyze_output_group = analyze_parser.add_argument_group(
        'Output Parameters'
    )

    aog.add_argument('--database-output-file','-dbo',
        default='eavesarp_dump.db',
        help='File to receive aggregated output')

    # WHITELISTS
    awfg = aw_filter_group = analyze_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )
    
    whitelist.add(awfg)
    sender_whitelist.add(awfg)
    target_whitelist.add(awfg)

    # BLACKLISTS    
    abfg = ab_filter_group = analyze_parser.add_argument_group(
        'Blacklist IP Filter Parameters'
    )

    blacklist.add(abfg)
    sender_blacklist.add(abfg)
    target_blacklist.add(abfg)

    # ============================
    # CAPTURE SUBCOMMAND ARGUMENTS
    # ============================

    capture_parser = subparsers.add_parser('capture',
        aliases=['c'],
        help='Capture and analyze ARP requests')

    # Set default cmd value
    capture_parser.set_defaults(cmd='capture')

    # General configuration Options
    general_group = capture_parser.add_argument_group(
        'General Configuration Parameters'
    )

    # Capture interfaces
    general_group.add_argument('--interface','-i',
        default='eth0',
        help='''Interface to sniff from.
        ''')
    
    general_group.add_argument('--active','-a',
        action='store_true',
        help='''Set this flag shoud you wish to attempt
        active ARP requests for target IPs. While this
        will confirm if a static IP configuration is
        affecting a given sender, it is an active reconnaissance
        technique.'''
    )

    # Stdout Configuration
    general_group.add_argument('--redraw-frequency','-rf',
        default=5,
        type=int,
        help='''Redraw the screen after each N packets
        are sniffed from the interface.
        ''')

    #disable_color.add(general_group)
    color_profile.add(general_group)
    resolve.add(general_group)

    # OUTPUT FILES
    output_group = capture_parser.add_argument_group(
        'Output Configuration Parameters'
    )
    database_output_file.add(output_group)

    # Analysis output file
    analysis_output_file.add(output_group)

    # PCAP output file
    output_group.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')

    # Address whitelist filters
    whitelist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )
    
    whitelist.add(whitelist_filter_group)
    sender_whitelist.add(whitelist_filter_group)
    target_whitelist.add(whitelist_filter_group)
    
    # Address blacklist filters
    blacklist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )

    blacklist.add(blacklist_filter_group)
    sender_blacklist.add(blacklist_filter_group)
    target_blacklist.add(blacklist_filter_group)

    args = main_parser.parse_args()

    if not args.cmd:
        main_parser.print_help() 
        exit()

    # =====================================
    # INITIALIZE WHITELIST/BLACKLIST TUPLES
    # =====================================

    sender_lists = Lists()
    target_lists = Lists()

    # Initialize white/black list objects for sender and target
    # addresses

    # Compile a regexp for variable names,
    # Used to dynamically pull and populate local variables.
    reg_list = re.compile(
        '^(?P<host_type>sender|target)_' \
        '(?P<list_type>(whitelist|blacklist))' \
        '(?P<files>_files)?'
    )

    # ==============================================
    # DYNAMICALLY POPULATE GENERAL WHITE/BLACK LISTS
    # ==============================================

    for list_type in ['white','black']:

        values = []

        vals = args.__dict__[list_type+'list']

        if not vals: continue

        for ival in vals:

            if not validate_ipv4(ival):

                if not Path(ival).exists():
                    print(
                        f'Inivalid ipv4 address and unknown file, skipping: {line}'
                    )
                else: vals += ipv4_from_file(ival)

            else: values.append(ival)

        for host_type in ['sender','target']:

            lst = locals()[host_type+'_lists'].__getattribute__(list_type)
            lst += values

    for arg_handle, arg_val in args.__dict__.items():

        # ======================================
        # DYNAMICALLY POPULATE WHITE/BLACK LISTS
        # ======================================

        '''
        The following logic accesses sender_lists and target_lists
        using the `locals()` builtin by detecting the appropriate
        variable by applying a regular expression to the name of
        each argument.
        '''

        # Apply the regex
        match = re.match(reg_list,arg_handle)

        # Irrelevant argument if no match is provided
        if not arg_val or not match:
            continue

        '''
        Extract the group dictionary, host_type, and list_type from
        the groups while removing list from the argument name. This
        translates the value of k to match up with a local variable
        of the same name.
        '''

        gd = match.groupdict() 
        host_type = gd['host_type'] # sender or target
        list_type = gd['list_type'].replace('list','') # white or black
        var_name = host_type+'_lists'
        
        # Get the appropriate lists object based on name, as crafted
        # from the argument handle, i.e. `sender_lists` or `target_lists`
        lst = locals()[var_name].__getattribute__(list_type)

        for line in arg_val:

            match = validate_ipv4(line)

            if not match:
                if not Path(line).exists():
                    print(
                        f'Invalid ipv4 address and unknown file, skipping: {line}'
                    )
                else:
                    lst += ipv4_from_file(line)
            else:
                lst.append(line)

        lst = list(set(lst))

    # ============================================
    # PREVENT DUPLICATE VALUES BETWEEN WHITE/BLACK
    # ============================================

    for handle in ['sender_lists','target_lists']:

        tpe = handle.split('_')[0]
        var = locals()[handle]

        counter = 0
        while counter < var.white.__len__():

            val = var.white[counter]

            # Use error thrown by list.index to determine if
            # a given value exists in both the white and black
            # lists.
            try:

                # When a value appears in both the black and white list
                # of a given lists object, remove them both.
                ind = var.black.index(val)
                var.white.__delitem__(counter)
                var.black.__delitem__(ind)

            except ValueError:

                # Increment the counter
                counter += 1
                continue

        var.white = list(set(var.white))
        var.black = list(set(var.black))
    

    # Load the whitelists/blacklists

    # ============================
    # BEGIN EXECUTING THE COMMANDS
    # ============================
    # Configure reverse name resolution
    #if args.disable_reverse_dns: resolve = False
    #else: resolve = True

    # Configure color printing
    #if args.disable_color: color = False
    #else: color = True

    args.color_profile = ColorProfiles[args.color_profile]

    # Analyze and exit
    if args.cmd == 'analyze':

        if not args.pcap_files and not args.sqlite_files:
            print('- Analyze command requires at least one input file.')
            exit()

        print(analyze(
                    **args.__dict__,
                    sender_lists=sender_lists,
                    target_lists=target_lists,
                    resolve=resolve
                ))

    # Capture and exit
    elif args.cmd == 'capture':
    
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
    
            pool = Pool(1)

            # Cache packets that will be written to output file
            pkts = []

            # Loop eternally
            while True:

    
                result = pool.apply_async(
                    async_sniff,
                    (
                        args.interface,
                        args.redraw_frequency,
                        sender_lists,
                        target_lists,
                        args.database_output_file,
                        args.analysis_output_file,
                        args.resolve,
                        args.color_profile,
                        True,
                        args.active
                    )
                )
    
                # Eternal loop while waiting for the result
                while not result.ready(): sleep(.2)
    
                # Clear the screen and print the results
                print('\x1b[2J\x1b[H')
                output,packets = result.get()

                # Capture packets for the output file
                if args.pcap_output_file: pkts += packets
                print(output)
    
        except KeyboardInterrupt:
    
            print('\n- CTRL^C Caught...')
            print('- Killing sniffer process and exiting')
    
        finally:
    
            # ===================
            # HANDLE OUTPUT FILES
            # ===================
    
            if args.pcap_output_file: wrpcap(args.pcap_output_file,pkts)
            if args.analysis_output_file:

                sess = create_db(args.database_output_file)

                with open(args.analysis_output_file,'w') as outfile:

                    outfile.write(
                        get_output(
                            sess,
                            sender_lists=sender_lists,
                            target_lists=target_lists,
                        )+'\n'
                    )
    
            # =========================
            # CLOSE THE SNIFFER PROCESS
            # =========================
    
            try:
    
                pool.close()
                result.wait(5)
    
            except KeyboardInterrupt:
    
                pool.terminate()
    
            pool.join()
    
            print('- Done! Exiting')
