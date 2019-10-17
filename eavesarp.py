#!/usr/bin/env python3

import argparse
import signal
from Eavesarp.eavesarp import *
from Eavesarp.color import ColorProfiles
from Eavesarp.decorators import *
from Eavesarp.validators import *
from Eavesarp.resolve import *
from Eavesarp.lists import *
from Eavesarp.logo import *
from Eavesarp.output import *
from Eavesarp import arguments
from Eavesarp.misc import get_interfaces
from sys import exit,stdout


# ====================================
# BUSH LEAGUE: Make arguments reusable
# ====================================

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

    arguments.dns_resolve.add(general_group)
    arguments.color_profile.add(general_group)
    arguments.output_columns.add(general_group)

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
    arguments.stale_only.add(aog)
    aog.add_argument('--database-output-file','-dbo',
        default='eavesarp_dump.db',
        help='File to receive aggregated output')
    arguments.csv_output_file.add(aog)
    arguments.force_sender.add(aog)

    # WHITELISTS
    awfg = aw_filter_group = analyze_parser.add_argument_group(
        'Whitelist IP Filter Parameters'
    )

    arguments.whitelist.add(awfg)
    arguments.sender_whitelist.add(awfg)
    arguments.target_whitelist.add(awfg)

    # BLACKLISTS
    abfg = ab_filter_group = analyze_parser.add_argument_group(
        'Blacklist IP Filter Parameters'
    )

    arguments.blacklist.add(abfg)
    arguments.sender_blacklist.add(abfg)
    arguments.target_blacklist.add(abfg)

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
        'General Configuration Parameters',
        '''Determine the appropriate sniffer interface and
        how frequently to redraw the output table, which occurs
        after the capture of n number of packets.
        '''
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

    resolution_group = capture_parser.add_argument_group(
        'Active Resolution Parameters',
        '''Enable DNS and ARP resolution.'''
    )

    resolution_group.add_argument('--arp-resolve','-ar',
        action='store_true',
        help='''Perform active ARP resolution for each target.'''
    )
    arguments.dns_resolve.add(resolution_group)

    # OUTPUT FILES
    output_group = capture_parser.add_argument_group(
        'Output Configuration Parameters',
        '''Determine output files and the structure
        of the table drawn to stdout during execution.
        '''
    )

    arguments.stale_only.add(output_group)
    arguments.database_output_file.add(output_group)

    # PCAP output file
    output_group.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')

    arguments.output_columns.add(output_group)
    
    output_group.add_argument('--display-false','-ds',
        action='store_true',
        help='''Enables display of false values in output columns.
        ''')
    
    arguments.force_sender.add(output_group)
    arguments.color_profile.add(output_group)

    # Address whitelist filters
    whitelist_filter_group = capture_parser.add_argument_group(
        'Whitelist IP Filter Parameters',
        '''Specify which IPs to show in output. Expects a combination
        of space delimted values. Either IP addresses or file names
        containing newline delimited IP addresses are expected. Mix
        and match is supported.'''
    )

    arguments.whitelist.add(whitelist_filter_group)
    arguments.sender_whitelist.add(whitelist_filter_group)
    arguments.target_whitelist.add(whitelist_filter_group)

    # Address blacklist filters
    blacklist_filter_group = capture_parser.add_argument_group(
        'Blacklist IP Filter Parameters',
        '''IPs to be suppressed from the output table. Expects a
        combination of space delimted values. Either IP addresses or
        file names containing newline delimited IP addresses are 
        expected. Mix and match is supported.
        '''
    )

    arguments.blacklist.add(blacklist_filter_group)
    arguments.sender_blacklist.add(blacklist_filter_group)
    arguments.target_blacklist.add(blacklist_filter_group)

    # ==========================
    # LIST INTERFACES SUBCOMMAND
    # ==========================

    lip = list_interfaces_parser = subparsers.add_parser('list',
        aliases=['l'],
        help='List available network interfaces')
    lip.set_defaults(cmd='list')

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
        validate_columns(args.output_columns)
    elif args.cmd == 'list':
        print('Getting network interfaces...')
        print('\n'+get_interface_table()+'\n')
        print('Exiting!')
        exit()
    else:
        print('- Output columns are required')
        print('Exiting!')
        exit()

    # =====================================
    # INITIALIZE WHITELIST/BLACKLIST TUPLES
    # =====================================

    sender_lists, target_lists = initialize_lists(
        **{k:v for k,v in args.__dict__.items() if k.endswith('list')}
    )

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

    # Capture and exit
    elif args.cmd == 'capture':

        interfaces = get_interfaces()
        if args.interface not in interfaces or not interfaces[args.interface][1]:
            valids = ', '.join([i for i,vs in interfaces.items() if vs[1]])
            print(f'Invalid interface provided: {args.interface}' \
            f'\n\nValid interfaces:\n\n{get_interface_table(True)}\n' \
            '\nFYI: An interface is valid only when it has an IP\n\n' \
            'Exiting!')
            exit()


        capture(**args.__dict__,
            sender_lists=sender_lists,
            target_lists=target_lists)

        print('- Done! Exiting')
