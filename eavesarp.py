#!/usr/bin/env python3
from scapy.all import sniff,ARP,wrpcap
from sys import stderr
from sys import stdout,stderr

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

    def __init__(self,ip,targets=None):

        if not targets: targets = HostList()
        self.targets = targets
        super().__init__(ip)

    def __lt__(self,val):

        if val.__class__ != Sender:
            raise TypeError(
                'Sender can be compared to another Sender object'
            )

        if self.targets.__len__() < val.targets.__len__():
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

    sen_len = 0
    tar_len = 0

    for sender in transactions:

        islen = sender.ip.__len__()
        if sen_len < islen: sen_len = islen

        for target in sender.targets:

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

        tar = sender.targets[0]
        output += '{sender_ip: <{sen_len}}{target_ip: <{tar_len}}{target_count: <2}\n'.format(
            sender_ip=sender.ip,
            sen_len=sen_len+spacer,
            tar_len=tar_len+spacer,
            target_ip=tar.ip,
            target_count=tar.count,
        )

        for tar in sender.targets[1:]:
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
    global senders
    global targets

    arp = packet.getlayer('ARP')
    target = arp.pdst
    sender = arp.psrc
    if senders and sender not in senders:
        return
    elif targets and target not in targets:
        return

    if sender not in transactions:
        sender = Sender(sender)
        transactions.append(sender)
        sender.targets.append(
            Target(target)
        )
    else:

        sender = transactions.get(sender)

        if target not in sender.targets:
            sender.targets.append(
                Target(target)
            )
        else:
            sender.targets.get(target).count += 1

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
senders             = []            # Senders filter
targets             = []            # Targets filter
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
    parser.add_argument('--sender-addresses','-ss',
        nargs='+',
        help='''Capture and analyze requests only when the
        sender address is in the argument supplied to this
        parameter. Input is a space delimited series of IP
        addresses.
        ''')
    parser.add_argument('--target-addresses','-ts',
        nargs='+',
        help='''Capture requests only when the target IP address
        is in the argument supplied to this parameter. Input is a
        space delimited series of IP addresses.
        ''')

    args = parser.parse_args()

    if args.sender_addresses: senders = args.sender_addresses
    if args.target_addresses: targets = args.target_addresses
    if args.redraw_frequency: redraw_frequency = args.redraw_frequency

    run_sniffer()
