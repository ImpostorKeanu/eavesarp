#!/usr/bin/env python3

from Eavesarp.decorators import *
from pathlib import Path

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

def filter_lists(sender_lists,target_lists,sender,target):

    '''
    In situations where only a single IP addresses is whitelisted
    for both target and sender, then a valid record would be when
    a host is resolving the MAC for itself -- which will never
    happen.  

    Worked around this issue by determining if the whitelists
    for for both the sender and target are identical and have
    a length of 1 and then determining if the ip address is in
    the whitelist for either Lists() object.
    '''

    if sender_lists.white and sender_lists.white == target_lists.white:

        if sender_lists.check(sender) or target_lists.check(target):
            return True
        else:
            return False

    elif sender_lists.black and sender_lists.black == target_lists.black:

        if not sender_lists.check(sender) or not target_lists.check(target):
            return False
        else:
            return True

    else:

        if not sender_lists.check(sender) or not \
                target_lists.check(target):
            return False
        else:
            return True

@validate_file_presence
def ipv4_from_file(infile):

    addrs = []
    with open(infile) as lines:

        for line in lines:

            line = line.strip()
            if validate_ipv4(line): addrs.append(line)
            else: continue
    
    return addrs

def load_lists(values=None):

    values = values or []

    output = []

    for val in values:

        if not validate_ipv4(val):

            if not Path(val).exists():

                print(
                    f'Invalid ipv4 address and unknown file, skipping: {val}'
                )

            else: output += ipv4_from_file(val)

        else: output.append(val)

    return output

def initialize_lists(whitelist=None,blacklist=None,
        sender_whitelist=None,sender_blacklist=None,
        target_whitelist=None,target_blacklist=None):

    whitelist = load_lists(whitelist or [])
    blacklist = load_lists(blacklist or [])

    sender_lists = Lists(
        white=load_lists(sender_whitelist or []),
        black=load_lists(sender_blacklist or [])
    )

    target_lists = Lists(
        white=load_lists(target_whitelist or []),
        black=load_lists(target_blacklist or [])
    )

    # ==================================
    # POPULATE GENERAL WHITE/BLACK LISTS
    # ==================================

    for list_type in ['white','black']:

        values = locals()[list_type+'list']

        # Adding ips to both sender white/black lists
        for host_type in ['sender','target']:

            lst = locals()[host_type+'_lists'].__getattribute__(list_type)
            lst += values

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

    return sender_lists,target_lists
