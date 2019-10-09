#!/usr/bin/env python3

from Eavesarp.output import COL_ORDER,COL_MAP
from Eavesarp.color import ColorProfiles

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
    help='''Target IP addresses that should be ignored.
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
    %(default)s. Valid Values: 
    '''+', '.join(list(COL_MAP.keys())))

stale_only = Argument('--stale-only','-so',
    action='store_true',
    help='''Only display records with a stale target.
    ''')

# Reverse DNS Configuration
dns_resolve = Argument('--dns-resolve','-dr',
    action='store_true',
    help='''Enable active DNS resolution.
    ''')

color_profile = Argument('--color-profile','-cp',
    default='default',
    choices=list(ColorProfiles.keys()),
    help='''Color profile to use. Set to "disable" to remove color
    altogether.''')

force_sender = Argument('--force-sender','-fs',
    action='store_true',
    help='''Force sender information for all table rows.
    ''')

color_profile = Argument('--color-profile','-cp',
    default='default',
    choices=list(ColorProfiles.keys()),
    help=''''Color profile to use. Set to "disable" to remove color
    altogether.''')
