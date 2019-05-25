#!/usr/bin/env python3
import re
from scapy.all import sniff,ARP,wrpcap
from pathlib import Path
from sys import stdout
from collections import namedtuple
from tabulate import tabulate

Lists = namedtuple('Lists',['white','black'],defaults=([],[],))

# ================
# CAPE CONVENIENCE
# ================

# ----------
# DECORATORS
# ----------

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


def validate_host(func):
    '''Decorator to facilitate easy validation of input objects.
    '''

    def wrapper(self, item, *args, **kwargs):

        if Host not in item.__class__.__mro__:
            raise TypeError(
                'host argument must be of type Host'
            )

        return func(self, item, *args, **kwargs)

    return wrapper

vfp = validate_file_presence
vpu = validate_packet_unpack
vh = validate_host

# ---------
# FUNCTIONS
# ---------

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

@validate_file_presence
def import_host_list(fname):
    '''Import lines from a list of IP addresses.
    '''

    with open(fname) as infile:
        output = [l.strip() for l in infile]

    return list(set(output))

def unpack_arp(arp):
    '''Validate a packet while returning the target and sender
    in a tuple: `(target,sender)`
    '''

    return  arp.pdst,arp.psrc

def unpack_packet(packet):

    return unpack_arp(packet.getlayer('ARP'))

# =======================================
# HOST/HOSTLIST ABSTRACTIONS FOR QUERYING
# =======================================

class Host:

    def __init__(self,ip,*args,**kwargs):

        self.ip = ip

    def __eq__(self, val):
        '''Allow comparison between either string or Host objects.
        '''
        
        if hasattr(val,'ip') and val.ip == self.ip:
            return True
        elif val.__class__ == str and val == self.ip:
            return True
        else:
            return False

class HostList(list):
    '''Simple list that enforces type of Host on appended objects.
    '''

    @validate_host
    def append(self, item):
        '''Override `append` to enforce type.
        '''

        super().append(item)

    def get(self, item):
        '''Get all objects that match the IP or host object. `__eq__`
        for `Host()` has been overridden to handle this.
        '''
        
        for host in self:
            if host == item: return host

        return None

    def to_table(self,reverse=False):

        rows = []

        for sender in sorted(self,reverse=reverse):

            rows += sender.to_rows()

        return rows

class Sender(Host):
    '''Descendent of Host that will be associated with a list of
    target addresses (ARP requests).
    '''

    def __init__(self,ip,targets=None):
        '''Assure that the targets parameters is a HostList() object.
        '''

        if not targets: targets = HostList()
        self.targets = targets
        super().__init__(ip)

    def __lt__(self,val):
        '''Convenience for sorting by hosts with the greatest
        number of target resolutions.
        '''

        if val.__class__ != Sender:
            raise TypeError(
                'Sender can be compared only to Sender objects'
            )

        arp_count = 0
        for t in self.targets: arp_count += t.count

        varp_count = 0
        for t in val.targets: arp_count += t.count

        if self.targets.__len__()+arp_count >= (
                    val.targets.__len__()+varp_count
                ):
            return False
        else:
            return True

    def to_rows(self):

        rows = []

        rows.append(
            [self.ip,self.targets[0].ip,self.targets[0].count]
        )

        for target in self.targets[1:]:
            rows.append(
                ['',target.ip,target.count]
            )

        return rows

class Target(Host):
    '''Host descendent that represents the target of a broadcasted
    ARP request.
    '''

    def __init__(self,ip,count=1):
        '''Initialize the count parameter.
        '''

        self.count = count
        super().__init__(ip)

    def __lt__(self, val):
        '''Less-than function to support sorting. Can accept integer
        values as well, which are compared with the `count` attribute.
        '''

        if val.__class__ == Target:
            val = val.count
        elif val.__class__ == int:
            val = val
        else:
            raise TypeError(
                'comparison must occur with an integer or Target object'
            )

        if val < self.count: return True
        else: return False

def get_output(transactions,reverse=True):

    if not transactions:
        output = '- No accepted ARP requests captured\n' \
        '- If this is unexpected, check your whitelist/blacklist configuration'
        return output

    return tabulate(
        transactions.to_table(),
        headers=['Target','Sender','Count']
    )

@validate_packet_unpack
def filter_packet(packet,sender_lists,target_lists):
    '''Filter an individual packet. This should be executed in the `lambda`
    supplied to `do_sniff`. `sender_lists` and `target_lists` should be namedtuple
    objects of type `List()`.
    '''

    if not packet: return False
    target,sender = packet

    if sender_lists.black and sender in sender_lists.black:
        return False
    elif target_lists.black and target in target_lists.black:
        return False

    if sender_lists.white and sender not in sender_lists.white:
        return False
    elif target_lists.white and target not in target_lists.white:
        return False

    return packet

@unpack_packets
def handle_packets(packets,transactions):
    '''Consume a list of packets, convert them to Host objects, and then add
    them to the Transaction list for querying.
    '''

    for packet in packets:

        target,sender = packet
    
        # Handle unknown sender
        if sender not in transactions:
    
            sender = Sender(sender)
            transactions.append(sender)
            sender.targets.append(
                Target(target)
            )
    
        # Handle known sender
        else:
    
            sender = transactions.get(sender)
    
            if target not in sender.targets:
                sender.targets.append(
                    Target(target)
                )
            else:
                sender.targets.get(target).count += 1

    return transactions

def do_sniff(interfaces,redraw_frequency,sender_lists,target_lists):
    '''Start the sniffer while filtering for WHO-HAS broadcast requests.
    '''

    return sniff(iface=interfaces,
        lfilter=lambda pkt: filter_packet(pkt,sender_lists,target_lists),
        count=redraw_frequency
    )
   

if __name__ == '__main__':

    # =============
    # BUILD THE CLI
    # =============

    import argparse
    parser = argparse.ArgumentParser(
        'Analyze ARP requests all eaves-like'
    )

    general_group = parser.add_argument_group(
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

    output_group = parser.add_argument_group('Output Configuration Parameters')

    # Output files
    output_group.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')
    output_group.add_argument('--analysis-output-file','-aof',
        help='''Name of file to receive analysis output.
        ''')

    # Address filters
    sender_filter_group = parser.add_argument_group(
        'Sender IP Filter Parameters'
    )

    sender_filter_group.add_argument('--sender-whitelist','-sw',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')

    sender_filter_group.add_argument('--sender-whitelist-files','-swfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid senders.
        ''')

    sender_filter_group.add_argument('--sender-blacklist','-sb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')
    
    sender_filter_group.add_argument('--sender-blacklist-files','-sbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid senders.
        ''')
    
    target_filter_group = parser.add_argument_group(
        'Target IP Filter Parameters'
    )

    target_filter_group.add_argument('--target-whitelist','-tw',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')

    target_filter_group.add_argument('--target-whitelist-files','-twfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid targets.
        ''')
    
    target_filter_group.add_argument('--target-blacklist-files','-tbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid targets.
        ''')

    target_filter_group.add_argument('--target-blacklist','-tb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')

    args = parser.parse_args()

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
        #
        # Logic crafts variable names so they can be populated
        # using the `locals()[variable_name]` builtin.
        #
        # Capture groups defined in `reg_list` are used to detect
        # the host_type, list_type, and if the argument represents
        # a file name from which to import address lines.

        # Apply the regex
        match = re.match(reg_list,arg_handle)

        # Irrelevant argument if no match is provided
        if not arg_val or not match:
            continue

        # Extract the group dictionary, host_type, and list_type from
        # the groups while removing list from the argument name. This
        # translates the value of k to match up with a local variable
        # of the same name.
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

    # =======================================
    # BEGIN CAPTURING AND DUMPING ARP PACKETS
    # =======================================
    

    print(
        '- Initializing capture\n- This may take time depending '\
        'on network traffic and filter configurations'
    )


    try:

        transactions = HostList()

        # Infinite loop until CTRL^C
        while True:

            # Capture more packets
            packets = do_sniff(args.interfaces, args.redraw_frequency, sender_lists, target_lists)

            # Convert packets to transactions
            transactions = handle_packets(packets, transactions) 

            # Clear the screen and write to stdout
            stdout.write('\x1b[2J\x1b[H')
            print(get_output(transactions))

    except KeyboardInterrupt:

        print('- CTRL^C Caught...')

    finally:

        if args.analysis_output_file:

            print('- Writing analysis file')
            with open(args.analysis_output_file,'w') as outfile:
                outfile.write(get_output()+'\n')

        if args.pcap_output_file:

            print('- Writing pcap file')
            wrpcap(args.pcap_output_file,pkts)

        print('- Exiting')
