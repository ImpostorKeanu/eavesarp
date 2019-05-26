#!/usr/bin/env python3
import re
from scapy.all import sniff,ARP,wrpcap,rdpcap
from pathlib import Path
from time import sleep
from os import remove
from sys import stdout
from collections import namedtuple
from tabulate import tabulate
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func, text, ForeignKeyConstraint, UniqueConstraint
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import relationship, backref, sessionmaker, close_all_sessions
from sqlalchemy.ext.declarative import declarative_base
from multiprocessing.pool import Pool
from dns import reversename, resolver
import colored

from IPython import embed
from sys import exit

Lists = namedtuple('Lists',['white','black'],defaults=([],[],))

Base = declarative_base()

class IP(Base):
    '''IP model.
    '''

    __tablename__ = 'ip'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False, unique=True,
            doc='IP address value')
    ptr = relationship('PTR', back_populates='ip')
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
#    return  arp.pdst,arp.psrc

def unpack_packet(packet):
    '''Extract and return the ARP layer from a packet object.
    '''

    return unpack_arp(packet.getlayer('ARP'))

def check_lists(ip,lists):
    '''Check an IP address value against a List() namedtuple
    object.
    '''

    if lists.black and ip in lists.black:
        return False
    elif lists.white and ip not in lists.white:
        return False

    return True

def get_output(db_session,order_by=desc,sender_lists=None,
        target_lists=None,ptr=False,color=False,resolve=True):
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

        if resolve:

            sptr = ''
            tptr = ''

            if t.sender.ptr: sptr = t.sender.ptr[0].value
            if t.target.ptr: tptr = t.target.ptr[0].value
        
            sender = t.sender.value
            target = t.target.value

            if sender_lists and not check_lists(sender,sender_lists):
                continue
            if target_lists and not check_lists(target,target_lists):
                continue


            # Building table rows
            if sender not in rowdict:
                # Initialize new sender IP with initial row
                rowdict[sender] = [[sender,target,t.count,sptr,tptr]]
            else:
                # Add new row to known sender IP
                rowdict[sender].append(['',target,t.count,'',tptr])
        else:
            
            sender = t.sender.value
            target = t.target.value

            if sender_lists and not check_lists(sender,sender_lists):
                continue
            if target_lists and not check_lists(sender,target_lists):
                continue

            # Building table rows
            if sender not in rowdict:
                # Initialize new sender IP with initial row
                rowdict[sender] = [[sender,target,str(t.count)]]
            else:
                # Add new row to known sender IP
                rowdict[sender].append(['',target,str(t.count)])

    # Restructure dictionary into a list of rows
    rows = []
    counter = 0
    for sender,irows in rowdict.items():
        counter += 1

        if color:

            if counter % 2:
                rows += irows
            else:
                rows += [[colored.stylize(v, odd_style) for v in r] for r in irows]

        else:
            rows += irows

    # Build the header
    headers = ['Sender IP','Target IP','WHO-HAS Count']
    if resolve: headers += ['Sender PTR','Target PTR']

    if color: headers = [
        colored.stylize(v, header_style) for v in headers
    ]

    return tabulate(
            rows,
            headers=headers)

header_style = colored.attr('bold')
odd_style = colored.fg(244)

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
    supplied to `do_sniff`. `sender_lists` and `target_lists` should be namedtuple
    objects of type `List()`.
    '''

    if not packet: return False
    sender,target = packet

    if sender_lists:
        if not check_lists(sender,sender_lists):
            return False
    if target_lists:
        if not check_lists(target,target_lists):
            return False

    return packet

def get_or_create_ip(ip,db_session,resolve=False):

    db_ip = db_session.query(IP).filter(IP.value==ip).first()

    if not db_ip:

        ip = IP(value=ip)
        db_session.add(ip)
        db_session.commit()

        # Obtain and set the PTR record for a given IP
        if resolve:
            ptr = reverse_resolve(ip.value)

            if ptr:

                db_session.add(
                    PTR(ip_id=ip.id,value=ptr)
                )

            db_session.commit()

    else: ip = db_ip

    return ip

@unpack_packets
def handle_packets(packets,db_session,resolve=False):

    for packet in packets:

        sender,target = packet

        # Determine if target/sender IP is in database
          # if not, create it
        sender = get_or_create_ip(packet[0],db_session,resolve)
        target = get_or_create_ip(packet[1],db_session,resolve)

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
   
def async_sniff(interfaces, redraw_frequency, sender_lists,
        target_lists, dbfile, analysis_output_file=None, resolve=False, 
        color=False, verbose=False):
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
        stdout.write('\x1b[2J\x1b[H')
        stdout.write(
            get_output(
                sess,
                sender_lists=sender_lists,
                target_lists=target_lists,
                color=color
            )
        )

    # Capture packets
    packets = do_sniff(interfaces,
            redraw_frequency, sender_lists,
            target_lists)

    # Handle packets (to the db they go, yo)
    handle_packets(packets,sess,resolve)

    return get_output(
            sess,sender_lists=sender_lists,
            target_lists=target_lists,color=color),packets

def analyze(database_output_file, sender_lists=None, target_lists=None,
        analysis_output_file=None, pcap_files=[], sqlite_files=[],
        color=False, *args, **kwargs):
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

        for t in isess.query(Transaction).all():

            sender = get_or_create_ip(t.sender.value,outdb_sess)
            target = get_or_create_ip(t.target.value,outdb_sess)

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
            color=color)

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

    sender_whitelist = Argument('--sender-whitelist','-sw',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')

    sender_whitelist_files = Argument('--sender-whitelist-files','-swfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid senders.
        ''')

    target_whitelist = Argument('--target-whitelist','-tw',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')
    
    target_whitelist_files = Argument('--target-whitelist-files','-twfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid targets.
        ''')

    sender_blacklist = Argument('--sender-blacklist','-sb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
    
    sender_blacklist_files = Argument('--sender-blacklist-files','-sbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid senders.
        ''')
    
    target_blacklist = Argument('--target-blacklist','-tb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
        
    target_blacklist_files = Argument('--target-blacklist-files','-tbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid targets.
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

    aog = analyze_output_group = analyze_parser.add_argument_group(
        'Output Parameters'
    )

    database_output_file.add(aog)
    analysis_output_file.add(aog)

    awfg = aw_filter_group = analyze_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )
    
    sender_whitelist.add(awfg)
    sender_whitelist_files.add(awfg)
    target_whitelist.add(awfg)
    target_whitelist_files.add(awfg)
    
    abfg = ab_filter_group = analyze_parser.add_argument_group(
        'Black IP Filter Parameters'
    )

    sender_blacklist.add(abfg)
    sender_blacklist_files.add(abfg)
    target_blacklist.add(abfg)
    target_blacklist_files.add(abfg)

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
    general_group.add_argument('--interfaces','-i',
        default=['eth0'],
        nargs='+',
        help='''Interfaces to sniff from.
        ''')

    # Stdout Configuration
    general_group.add_argument('--redraw-frequency','-rf',
        default=5,
        type=int,
        help='''Redraw the screen after each N packets
        are sniffed from the interface.
        ''')

    # Make color optional
    general_group.add_argument('--disable-color','-dc',
        action='store_true',
        help='''Disable colored printing''')

    # Reverse DNS Configuration
    general_group.add_argument('--disable-reverse-dns','-drdns',
        action='store_true',
        help='''Disable reverse resolution of IP addresses.
        ''')

    # Output files
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
    
    sender_whitelist.add(whitelist_filter_group)
    sender_whitelist_files.add(whitelist_filter_group)
    target_whitelist.add(whitelist_filter_group)
    target_whitelist_files.add(whitelist_filter_group)
    
    # Address blacklist filters
    blacklist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )

    sender_blacklist.add(blacklist_filter_group)
    sender_blacklist_files.add(blacklist_filter_group)
    target_blacklist.add(blacklist_filter_group)
    target_blacklist_files.add(blacklist_filter_group)

    args = main_parser.parse_args()

    if not args.cmd: main_parser.print_help() 

    # =====================================
    # INITIALIZE WHITELIST/BLACKLIST TUPLES
    # =====================================

    # Initialize white/black list objects for sender and target
    # addresses
    sender_lists = Lists()
    target_lists = Lists()

    # Compile a regexp for variable names,
    # Used to dynamically pull and populate local variables.
    reg_list = re.compile(
        '^(?P<host_type>sender|target)_' \
        '(?P<list_type>(whitelist|blacklist))' \
        '(?P<files>_files)?'
    )

    # Load the whitelists/blacklists
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
        
        # Get the appropriate lists object based on name, as crafted
        # from the argument handle, i.e. `sender_lists` or `target_lists`
        lst = locals()[host_type+'_lists'].__getattribute__(list_type)

        # Files flag is used to determine if records should be slurped
        # from a series of files
        if gd['files']: files = True
        else: files = False

        if files:
            # Import lines from files
            for fname in arg_val: lst += import_host_list(fname)
        else:
            # Append lines from value
            lst += arg_val

        lst = set(lst)

    # ============================
    # BEGIN EXECUTING THE COMMANDS
    # ============================

    # Analyze and exit
    if args.cmd == 'analyze':

        if not args.pcap_files and not args.sqlite_files:
            raise Exception(
                'Analyze command requires at least one input file'
            )

        print(analyze(**args.__dict__))

    # Capture and exit
    elif args.cmd == 'capture':

        # Configure reverse name resolution
        if args.disable_reverse_dns: resolve = False
        else: resolve = True

        # Configure color printing
        if args.disable_color: color = False
        else: color = True
    
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
                        args.interfaces,
                        args.redraw_frequency,
                        sender_lists,
                        target_lists,
                        args.database_output_file,
                        args.analysis_output_file,
                        resolve,
                        color,
                        True
                    )
                )
    
                # Eternal loop while waiting for the result
                while not result.ready(): sleep(.2)
    
                # Clear the screen and print the results
                stdout.write('\x1b[2J\x1b[H')
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
                            color=False
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
