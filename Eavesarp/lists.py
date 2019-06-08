#!/usr/bin/env python3

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
