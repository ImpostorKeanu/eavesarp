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
