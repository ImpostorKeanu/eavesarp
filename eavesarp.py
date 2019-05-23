#!/usr/bin/env python3
from scapy.all import sniff,ARP,wrpcap
from pathlib import Path
from sys import stderr
from sys import stdout,stderr

def validate_file_presence(func):

    def wrapper(fname,*args,**kwargs):

        p = Path(fname)
        if p.exists() and p.is_file():
            return func(fname,*args,**kwargs)
        else:
            raise Exception(
                f'File not found: {fname}'
            )

    return wrapper

vfp = validate_file_presence

@vfp
def import_host_list(fname):

    with open(fname) as infile:
        output = [l.strip() for l in infile]

    return output

class Host:

    def __init__(self,ip,*args,**kwargs):

        self.ip = ip

    def __eq__(self, val):
        
        if hasattr(val,'ip') and val.ip == self.ip:
            return True
        elif val.__class__ == str and val == self.ip:
            return True
        else:
            return False

    @staticmethod
    def validate_host(func):

        def wrapper(self, item, *args, **kwargs):

            if Host not in item.__class__.__mro__:
                raise TypeError(
                    'HostList accepts only objects that descend from Host'
                )

            return func(self, item, *args, **kwargs)

        return wrapper

class HostList(list):

    @Host.validate_host
    def append(self, item):
        super().append(item)

    def get(self, item):
        
        for host in self:
            if host == item: return host

        return None

class Sender(Host):

    def __init__(self,ip,target_whitelist=None):

        if not target_whitelist: target_whitelist = HostList()
        self.target_whitelist = target_whitelist
        super().__init__(ip)

    def __lt__(self,val):

        if val.__class__ != Sender:
            raise TypeError(
                'Sender can be compared to another Sender object'
            )

        if self.target_whitelist.__len__() < val.target_whitelist.__len__():
            return False
        else:
            return True

class Target(Host):

    def __init__(self,ip,count=1):

        self.count = count
        super().__init__(ip)

    def __lt__(self, val):

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

def get_output():

    global transactions

    if not transactions:
        output = '- No accepted ARP requests captured\n' \
        '- If this is unexpected, check your whitelist/blacklist configuration'
        return output

    sen_len = 0
    tar_len = 0

    for sender in transactions:

        islen = sender.ip.__len__()
        if sen_len < islen: sen_len = islen

        for target in sender.target_whitelist:

            itlen = target.ip.__len__()
            if itlen > tar_len: tar_len = itlen

    spacer = 4
    output = '{: <{sen_len}}{: <{tar_len}}{: <2}\n'.format(
        'Sender',
        'Target',
        'Count',
        sen_len=sen_len+spacer,
        tar_len=tar_len+spacer
    )
    output += '{:-<{sen_len}}{:-<{tar_len}}{:-<5}\n'.format(
        '',
        '' ,
        '',
        sen_len=sen_len+spacer,
        tar_len=tar_len+spacer
    )
    for sender in transactions:

        tar = sender.target_whitelist[0]
        output += '{sender_ip: <{sen_len}}{target_ip: <{tar_len}}{target_count: <2}\n'.format(
            sender_ip=sender.ip,
            sen_len=sen_len+spacer,
            tar_len=tar_len+spacer,
            target_ip=tar.ip,
            target_count=tar.count,
        )

        for tar in sender.target_whitelist[1:]:
            output += '{buff: <{sen_len}}{target_ip: <{tar_len}}{target_count: <2}\n'.format(
                buff='',
                target_ip=tar.ip,
                sen_len=sen_len+spacer,
                tar_len=tar_len+spacer,
                target_count=tar.count,
            )

    return output

def filter(packet,file=stdout):

    global transactions
    global sender_whitelist
    global sender_blacklist
    global target_whitelist
    global target_blacklist

    arp = packet.getlayer('ARP')
    target = arp.pdst
    sender = arp.psrc

    if sender_blacklist and sender in sender_blacklist:
        return None
    elif target_blacklist and target in target_blacklist:
        return None

    if sender_whitelist and sender not in sender_whitelist:
        return None
    elif target_whitelist and target not in target_whitelist:
        return None

    # Handle unknown sender
    if sender not in transactions:

        sender = Sender(sender)
        transactions.append(sender)
        sender.target_whitelist.append(
            Target(target)
        )

    # Handle known sender
    else:

        sender = transactions.get(sender)

        if target not in sender.target_whitelist:
            sender.target_whitelist.append(
                Target(target)
            )
        else:
            sender.target_whitelist.get(target).count += 1

    return None

def do_sniff():

    global args
    global redraw_frequency

    return sniff(iface=args.interfaces,
        lfilter=lambda pkt: ARP in pkt and pkt.getlayer('ARP').op == 1,
        prn=filter,
        count=redraw_frequency
    )
    
def run_sniffer():

    global args

    pkts = []

    try:

        while True:
    
            if args.pcap_output_file:
                pkts += do_sniff()
            else:
                do_sniff()
    
            stdout.write('\x1b[2J\x1b[H')
            print(get_output())

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


transactions        = HostList()    # Track all transactions
sender_whitelist             = []            # Senders filter
sender_blacklist          = []
target_blacklist          = []
target_whitelist             = []            # Targets filter
redraw_frequency    = 5             # Redraw frequency

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser(
        'Analyze ARP requests all eaves-like'
    )

    # Capture configuration
    parser.add_argument('--interfaces','-i',
        default=['eth0'],
        nargs='+',
        help='''Interfaces to sniff from.
        ''')

    # Stdout Configuration
    parser.add_argument('--redraw-frequency','-rf',
        default=redraw_frequency,
        type=int,
        help='''Redraw the screen after each N packets
        are sniffed from the interface.
        ''')

    # Output files
    parser.add_argument('--pcap-output-file','-pof',
        help='''Name of file to dump captured packets
        ''')
    parser.add_argument('--analysis-output-file','-aof',
        help='''Name of file to receive analysis output.
        ''')

    # Address filters

    ## Whitelists
    parser.add_argument('--sender-whitelist','-sw',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')

    parser.add_argument('--sender-whitelist-files','-swfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid senders.
        ''')

    parser.add_argument('--target-whitelist','-tw',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')

    parser.add_argument('--target-whitelist-files','-twfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with valid targets.
        ''')

    ## Blacklists
    parser.add_argument('--sender-blacklist','-sb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')

    parser.add_argument('--sender-blacklist-files','-sbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid senders.
        ''')
    
    parser.add_argument('--target-blacklist-files','-tbfs',
        nargs='+',
        help='''Space delimited list of files containing newline
        delimited IP addresses associated with invalid targets.
        ''')

    parser.add_argument('--target-blacklist','-tb',
        nargs='+',
        help='''Sender IP addresses that should be ignored.
        ''')

    args = parser.parse_args()

    if args.redraw_frequency:
        redraw_frequency = args.redraw_frequency

    for k,v in args.__dict__.items():

        if not v: continue

        # Append hosts to lists
        if k.endswith('list'):

            globals()[k] += v

        # Append hosts to lists from files
        elif k.endswith('files'):

            lname = k.replace('_files','')
            local = globals()[lname]

            for fname in v:
                local += import_host_list(fname)

    run_sniffer()
