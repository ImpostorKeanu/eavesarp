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

from IPython import embed
from sys import exit

Lists = namedtuple('Lists',['white','black'],defaults=([],[],))

# ================
# CAPE CONVENIENCE
# ================

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

def get_output(db_session,order_by=desc,sender_lists=[],target_lists=[],ptr=False):
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

            # Building table rows
            if sender not in rowdict:
                # Initialize new sender IP with initial row
                rowdict[sender] = [[sender,target,t.count]]
            else:
                # Add new row to known sender IP
                rowdict[sender].append(['',target,t.count])

    # Restructure dictionary into a list of rows
    rows = []
    for sender,irows in rowdict.items():
        rows += irows

    # Build the header
    headers = ['Sender IP','Target IP','WHO-HAS Count']
    if resolve: headers += ['Sender PTR','Target PTR']

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
def filter_packet(packet,sender_lists,target_lists):
    '''Filter an individual packet. This should be executed in the `lambda`
    supplied to `do_sniff`. `sender_lists` and `target_lists` should be namedtuple
    objects of type `List()`.
    '''

    if not packet: return False
    sender,target = packet

    if not check_lists(sender,sender_lists) or not check_lists(
        target,target_lists):
        return False

    return packet

def get_or_create_ip(ip,db_session,resolve=False):

    commit_flag = False
    if not db_session.query(IP).filter(IP.value==ip).count():

        ip = IP(value=ip)
        db_session.add(ip)
        commit_flag = True


    else:

        ip = db_session.query(IP).filter(IP.value==ip).first()

    if commit_flag: 

        db_session.commit()

        if resolve:
            ptr = reverse_resolve(ip.value)

            if ptr:

                db_session.add(
                    PTR(ip_id=ip.id,value=ptr)
                )

            db_session.commit()

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
        target_lists, dbfile, resolve, verbose=False):
    '''This function should be started in a distinct process, allowing
    the one to CTRL^C during execution and gracefully exit the sniffer.
    Not starting the sniffer in a distinct process results in it blocking
    forever or until an inordinate number of keyboard interrupts occur.
    '''

    if not Path(dbfile).exists():

        if verbose: print(
            '- Initializing capture\n- This may take time depending '\
            'on network traffic and filter configurations'
        )
        sess = create_db(dbfile)

    else:
        
        sess = create_db(dbfile)
        stdout.write('\x1b[2J\x1b[H')
        stdout.write(get_output(sess))

    packets = do_sniff(interfaces,
            redraw_frequency, sender_lists,
            target_lists)

    handle_packets(packets,sess,resolve)

    return get_output(sess,resolve),packets

def analyze(database_output_file,analysis_output_file=None,
        pcap_files=[], sqlite_files=[], *args, **kwargs):

    outdb_sess = create_db(database_output_file,overwrite=True)

    # Handle sqlite files first
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

    for pfile in pcap_files:

        handle_packets(
            rdpcap(pfile),
            outdb_sess
        )

    return get_output(outdb_sess)

if __name__ == '__main__':

    # =============
    # BUILD THE CLI
    # =============

    import argparse
    main_parser = argparse.ArgumentParser(
        'Analyze ARP requests all eaves-like'
    )

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
    aog.add_argument('--database-output-file','-dof',
        default='eavesarp_dump.db',
        help='''Name of the SQLite database file to output.
        Default: %(default)s
        '''
    )
    aog.add_argument('--analysis-output-file','-aof',
        help='''Name of file to receive analysis output.
        '''
    )

    # ============================
    # CAPTURE SUBCOMMAND ARGUMENTS
    # ============================

    capture_parser = subparsers.add_parser('capture',
        aliases=['c'],
        help='Capture and analyze ARP requests')
    capture_parser.set_defaults(cmd='capture')

    general_group = capture_parser.add_argument_group(
        'General Configuration Parameters'
    )

    # Capture configuration
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

    # Reverse DNS Configuration
    general_group.add_argument('--disable-reverse-dns','-drdns',
        action='store_true',
        help='''Disable reverse resolution of IP addresses.
        ''')

    output_group = capture_parser.add_argument_group('Output Configuration Parameters')

    # Output files
    output_group.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')
    output_group.add_argument('--analysis-output-file','-aof',
        help='''Name of file to receive analysis output.
        ''')
    output_group.add_argument('--database-output-file','-dof',
        default='eavesarp.db',
        help='''Name of SQLite database file to output.
        Default: %(default)s
        '''
    )

    # Address filters

    whitelist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )
    
    whitelist_filter_group.add_argument('--sender-whitelist','-sw',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')

    whitelist_filter_group.add_argument('--sender-whitelist-files','-swfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid senders.
        ''')

    whitelist_filter_group.add_argument('--target-whitelist','-tw',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')
    
    whitelist_filter_group.add_argument('--target-whitelist-files','-twfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid targets.
        ''')

    blacklist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )

    blacklist_filter_group.add_argument('--sender-blacklist','-sb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
    
    blacklist_filter_group.add_argument('--sender-blacklist-files','-sbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid senders.
        ''')
    
    blacklist_filter_group.add_argument('--target-blacklist','-tb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
        
    blacklist_filter_group.add_argument('--target-blacklist-files','-tbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid targets.
        ''')

    args = main_parser.parse_args()

    if args.cmd == 'analyze':

        if not args.pcap_files and not args.sqlite_files:
            raise Exception(
                'Analyze command requires at least one input file'
            )

        print(analyze(**args.__dict__))

    elif args.cmd == 'capture':

        if args.disable_reverse_dns:
            resolve = False
        else:
            resolve = True

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
    
    
        try:
    
            # ==============
            # START SNIFFING
            # ==============
    
            '''
            The sniffer is started in a distinct process because Scapy
            will block forever when scapy.all.sniff is called. This allows
            us to interrupt execution of the sniffer by terminating the
            process.
            '''
    
            pool = Pool(1)
            pkts = []
            while True:
    
                result = pool.apply_async(
                    async_sniff,
                    (
                        args.interfaces,
                        args.redraw_frequency,
                        sender_lists,
                        target_lists,
                        args.database_output_file,
                        resolve,
                        True
                    )
                )
    
                while not result.ready():
                    sleep(.2)
    
                stdout.write('\x1b[2J\x1b[H')
                output,packets = result.get()

                if args.pcap_output_file:
                    pkts += packets

                print(output)
    
        except KeyboardInterrupt:
    
            print('- CTRL^C Caught...')
            print('- Killing sniffer process and exiting')
    
        finally:
    
            # ===================
            # HANDLE OUTPUT FILES
            # ===================
            
            if args.analysis_output_file:
    
                print('- Writing analysis file')
                with open(args.analysis_output_file,'w') as outfile:
                    outfile.write(get_output()+'\n')
    
            if args.pcap_output_file:
    
                print('- Writing pcap file')
                wrpcap(args.pcap_output_file,pkts)
    
            # =========================
            # CLOSE THE SNIFFER PROCESS
            # =========================
    
            try:
    
                pool.close()
                print('- Waiting for the process to finish...')
                result.wait(5)
    
            except KeyboardInterrupt:
    
                print('- Terminating sniffer process!')
                pool.terminate()
    
            print('- Joining the process')
            pool.join()
    
            print('- Exiting')
