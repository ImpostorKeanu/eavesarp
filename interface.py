#!/usr/bin/env python3

import argparse
from eavesarp.eavesarp import *
from eavesarp.color import ColorProfiles

# ===================
# CONSTANTS/FUNCTIONS
# ===================

# Regexp to validate ipv4 structure
ipv4_re = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

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

    resolve.add(general_group)
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

    # ===============
    # PARSE ARGUMENTS
    # ===============

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

    # ============================
    # BEGIN EXECUTING THE COMMANDS
    # ============================

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
