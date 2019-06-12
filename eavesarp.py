#!/usr/bin/env python3

import argparse
import signal
import pdb
import csv
from io import StringIO
from Eavesarp.eavesarp import *
from Eavesarp.color import ColorProfiles
from Eavesarp.decorators import *
from Eavesarp.validators import *
from Eavesarp.resolve import *
from Eavesarp.lists import *
from Eavesarp.logo import *
from sys import exit,stdout
from io import StringIO
# ===================
# CONSTANTS/FUNCTIONS
# ===================

COL_MAP = {
    'arp_count':'ARP#',
    'sender':'Sender',
    'sender_mac':'Sender MAC',
    'target':'Target',
    'target_mac':'Target MAC',
    'stale':'Stale',
    'sender_ptr':'Sender PTR',
    'target_ptr':'Target PTR',
    'target_forward':'Target PTR Forward',
    'mitm_op':'MITM',
    'snac':'SNAC',
}

COL_ORDER = [
    'snac',
    'sender',
    'target',
    'arp_count',
    'stale'
]


@validate_file_presence
def ipv4_from_file(infile):

    addrs = []
    with open(infile) as lines:

        for line in lines:

            line = line.strip()
            if validate_ipv4(line): addrs.append(line)
            else: continue
    
    return addrs

def build_snac(target,snacs,color_profile,display_false=True):


    snac = (False,True)[target in snacs]

    # Handle color profile
    if color_profile and color_profile.snac_emojis:

        # When the snac is valid or false should be
        # displayed
        if snac or not snac and display_false:
            snac = color_profile.snac_emojis[snac]
        else:
            snac = ''

    # When the sender isn't a snac
    elif not snac and not display_false:
        snac = ''

    return snac


def get_output_csv(db_session,order_by=desc,sender_lists=None,
        target_lists=None):

    # ==========================
    # HANDLE SENDER/TARGET LISTS
    # ==========================
    
    sender_lists = sender_lists or Lists()
    target_lists = target_lists or Lists()

    # ===============
    # PREPARE COLUMNS
    # ===============

    columns = list(COL_MAP.keys())

    # ====================
    # GET ALL TRANSACTIONS
    # ====================

    transactions = get_transactions(db_session,order_by)

    # =============================
    # WRITE CSVS TO STRINGIO OBJECT
    # =============================

    outfile = StringIO()
    writer = csv.writer(outfile)
    writer.writerow(columns)

    if 'snac' in columns: snacs = get_snacs(db_session)
    else: snacs = []

    # Write all transactions
    for t in transactions:

        for column in columns:

            writer.writerow([t.bfh('build_'+col,new_sender=True,display_false=True) for col in columns])

    outfile.seek(0)

    # Return the output
    return outfile

def get_snacs(db_session):

    snacs = []

    # Build the list of snacs
    snacs = db_session.query(IP) \
        .filter(IP.arp_resolve_attempted==True) \
        .filter(IP.mac_address==None) \
        .all()

    return snacs

def get_output_table(db_session,order_by=desc,sender_lists=None,
        target_lists=None,color_profile=None,dns_resolve=True,
        arp_resolve=False,columns=COL_ORDER,display_false=False):
    '''Extract transaction records from the database and return
    them formatted as a table.
    '''

    sender_lists = sender_lists or Lists()
    target_lists = target_lists or Lists()

    transactions = get_transactions(db_session,order_by)

    if not transactions:
        output = '- No accepted ARP requests captured\n' \
        '- If this is unexpected, check your whitelist/blacklist configuration'
        return output

    # ==============================
    # ADD A SNAC COLUMN IF REQUESTED
    # ==============================

    '''
    A host has a SNAC when it has no mac_address but has been
    targeted for ARP resolution. Since an IP object is generic,
    there is no attribute for 'stale' or 'snac', so a snac
    state must be inferred on the 'no mac and arp resolved' op.

    1. build a list of ip addresses that have no mac and have 
    been arp resolved
    2. as we build each table, check to see if the sender ip
    is in the list of snacs. if so and this is the first time
    a sender has been added to the table, then populate the
    cell with a value of True, False, or and emoji.
    '''

    if 'snac' in columns: snacs = get_snacs(db_session)
    else: snacs = []

    # =====================================================
    # ADD PTR/STALE COLUMNS WHEN ARP/DNS RESOLVE IS ENABLED
    # =====================================================

    if arp_resolve and not 'stale' in columns \
            and columns == COL_ORDER:
        columns.append('stale')

    if dns_resolve and columns == COL_ORDER:
        if not 'sender_ptr' in columns:
            columns.append('sender_ptr')
        if not 'target_ptr' in columns:
            columns.append('target_ptr')
        if not 'mitm_op' in columns:
            columns.append('mitm_op')

    # Organize all the records by sender IP
    rowdict = {}
    for t in transactions:

        smac = t.sender.mac_address

        sender = t.sender.value
        target = t.target.value

        # ====================
        # FILTER BY IP ADDRESS
        # ====================

        if not filter_lists(sender_lists,target_lists,sender,target):
            continue

        # Flag to determine if the sender is new
        if sender not in rowdict: new_sender = True
        else: new_sender = False

        row = []

        for col in columns:

            if col == 'snac':

                if new_sender:
                
                    row.append(
                        build_snac(t.target,snacs,color_profile,display_false)
                    )

                else:

                    row.append('')

            elif col == 'sender':

                if new_sender: row.append(sender)
                else: row.append('')

            elif col == 'target':

                row.append(target)

            elif col == 'stale':

                row.append(t.build_stale(color_profile,
                    display_false=display_false))

            else:

                if col == 'arp_count': col = 'count'

                row.append(
                    t.bfh('build_'+col,new_sender=new_sender,
                        display_false=display_false)
                )

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

    headers = [COL_MAP[col] for col in columns]

    # Color the headers
    if color_profile: headers = color_profile.style_header(headers)

    # Return the output as a table
    return tabulate(
            rows,
            headers=headers)

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

csv_output_file = Argument('--csv-output-file','-cof',
    default='',
    help='''Name of file to receive CSV output.
    '''
)

output_columns = Argument('--output-columns','-oc',
    default=COL_ORDER,
    nargs='+',
    help='''Space delimited list of columns to show in output.
    Columns will be displayed in the order as provided. Default:
    %(default)s
    ''')

# Reverse DNS Configuration
dns_resolve = Argument('--dns-resolve','-dr',
    action='store_true',
    help='''Enable active DNS resolution.
    ''')

color_profile = Argument('--color-profile','-cp',
    default='default',
    choices=list(ColorProfiles.keys()),
    help=''''Color profile to use. Set to "disable" to remove color
    altogether.''')

if __name__ == '__main__':

    # =============
    # BUILD THE CLI
    # =============

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

    dns_resolve.add(general_group)
    color_profile.add(general_group)
    output_columns.add(general_group)

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
    csv_output_file.add(aog)

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
    
    # Stdout Configuration
    general_group.add_argument('--redraw-frequency','-rf',
        default=5,
        type=int,
        help='''Redraw the screen after each N packets
        are sniffed from the interface.
        ''')

    general_group.add_argument('--display-false','-ds',
        action='store_true',
        help='''Enables display of false values in output columns.
        ''')

    color_profile.add(general_group)

    dns_resolve.add(general_group)
    
    general_group.add_argument('--arp-resolve','-ar',
        action='store_true',
        help='''Set this flag shoud you wish to attempt
        active ARP requests for target IPs. While this
        will confirm if a static IP configuration is
        affecting a given sender, it is an active reconnaissance
        technique.'''
    )

    # OUTPUT FILES
    output_group = capture_parser.add_argument_group(
        'Output Configuration Parameters'
    )
    database_output_file.add(output_group)

    # PCAP output file
    output_group.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')

    output_columns.add(output_group)

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

    # ===============
    # PARSE ARGUMENTS
    # ===============

    args = main_parser.parse_args()
    if not args.cmd:
        main_parser.print_help() 
        exit()

    # ============================
    # CHECKING COLUMN ORDER VALUES
    # ============================

    if hasattr(args,'output_columns'):

        if not args.output_columns:
            print('- Output columns are required')
            print('Exiting!')
            exit()

        vals = COL_MAP.keys()
        bad = [v for v in args.output_columns if not v in vals]

        if bad:

            print('- Invalid column values provided: ',','.join(bad))
            print('- Valid values: ',','.join(vals))
            print('Exiting!')
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
                        f'Invalid ipv4 address and unknown file, skipping: {ival}'
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

    # ============================
    # BEGIN EXECUTING THE COMMANDS
    # ============================

    args.color_profile = ColorProfiles[args.color_profile]

    # Analyze and exit
    if args.cmd == 'analyze':

        if not args.pcap_files and not args.sqlite_files:
            print('- Analyze command requires at least one input file.')
            exit()

        analyze(**args.__dict__,
                sender_lists=sender_lists,
                target_lists=target_lists)

        sess = create_db(args.database_output_file)
        print(
            get_output_table(
                sess,
                sender_lists=sender_lists,
                target_lists=target_lists,
                color_profile=args.color_profile,
                columns=args.output_columns))

        if args.csv_output_file:
            print(f'- Writing csv output to {args.csv_output_file}')
            with open(args.csv_output_file,'w') as outfile:
                outfile.write(
                    get_output_csv(
                        sess,
                        sender_lists=sender_lists,
                        target_lists=target_lists
                    ).read()
                )

    # Capture and exit
    elif args.cmd == 'capture':

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

            dbfile = args.database_output_file

            ptable = None
            pcount = 0
            # Handle new database file. When verbose, alert user that a new
            # capture must occur prior to printing results.

            arp_resolution = ('disabled','enabled')[args.arp_resolve]
            dns_resolution = ('disabled','enabled')[args.dns_resolve]

            print('\x1b[2J\x1b[H\33[F')
            print(logo+'\n')
            print(f'Capture interface: {args.interface}')
            print(f'ARP resolution:    {arp_resolution}')
            print(f'DNS resolution:    {dns_resolution}')
            sess = create_db(dbfile)
            if not Path(dbfile).exists():
                print('- Initializing capture\n- This may take time depending '\
                    'on network traffic and filter configurations')
            else:

                print(f'Requests analyzed: {pcount}\n')
                ptable = get_output_table(
                    sess,
                    sender_lists=sender_lists,
                    target_lists=target_lists,
                    dns_resolve=args.dns_resolve,
                    color_profile=args.color_profile,
                    arp_resolve=args.arp_resolve,
                    columns=args.output_columns,
                    display_false=args.display_false)
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
                    if args.pcap_output_file and packets: pkts += packets
                    
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
                        dns_resolve=args.dns_resolve,
                        color_profile=args.color_profile,
                        arp_resolve=args.arp_resolve,
                        columns=args.output_columns,
                        display_false=args.display_false)
                
                    print(f'Requests analyzed: {pcount}\n')
                    print(ptable)
                    
                # Do sniffing
                elif not sniff_result:
                   
                    sniff_result = pool.apply_async(
                        async_sniff,
                        (
                            args.interface,
                            args.redraw_frequency,
                            sender_lists,
                            target_lists,
                            args.database_output_file,
                        )
                    )

                # ==================
                # DNS/ARP RESOLUTION
                # ==================
   
                # Do reverse resolution
                if args.dns_resolve:

                    # Reset dns resolution results
                    if not dns_resolve_result or dns_resolve_result.ready():

                        to_resolve = sess.query(IP) \
                                .filter(IP.reverse_dns_attempted != True) \
                                .count()
    
                        if to_resolve:
                            
                           dns_resolve_result = pool.apply_async(
                                reverse_dns_resolve_ips,
                                (args.database_output_file,)
                            )
    
                # Do ARP resolution
                if args.arp_resolve:

                    if not arp_resolve_result or arp_resolve_result.ready():

                        to_resolve = sess.query(IP) \
                                .filter(IP.arp_resolve_attempted != True) \
                                .count()
    
                        if to_resolve:
    
                            arp_resolve_result = pool.apply_async(
                                arp_resolve_ips,
                                    (args.interface, args.database_output_file,)
                                )

                sleep(.2)

    
        except KeyboardInterrupt:
    
            print('\n- CTRL^C Caught...')
            sess.close()
    
        finally:
    
            # ===================
            # HANDLE OUTPUT FILES
            # ===================
    
            if args.pcap_output_file: wrpcap(args.pcap_output_file,pkts)
    
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
    
            print('- Done! Exiting')
