#!/usr/bin/env python3

import colored
from emoji import emojize

class ColorProfile:

    def __init__(self,even_color,odd_color,header_color,
            header_bold=True,stale_emoji=None,snac_emojis=None):

        self.snac_emojis = snac_emojis or (False,True)

        self.even_style = colored.fg(even_color)
        self.odd_style = colored.fg(odd_color)

        self.header_style = colored.fg(header_color)
        if header_bold: self.header_style += colored.attr('bold')

        self.stale_emoji=stale_emoji

    def style_header(self,headers):
        return self.style_list(headers,self.header_style)

    def style_even(self,values):
        return self.style_list(values,self.even_style)

    def style_odd(self,values):
        return self.style_list(values,self.odd_style)

    def style_list(self, values, style):
        return [colored.stylize(v,style) for v in values]

ColorProfiles = {
    'disable':None,
    # Practical color profiles
    'default':ColorProfile(even_color=254, odd_color=244,
            header_color=254, header_bold=True),
    '1337':ColorProfile(even_color=28, odd_color=118,
            header_color=28, header_bold=True),
    'agent_orange':ColorProfile(even_color=166, odd_color=179,
            header_color=166, header_bold=True),
    'evil':ColorProfile(even_color=124, odd_color=9,
            header_color=9, header_bold=True),
    'cobalt':ColorProfile(even_color=245, odd_color=26,
            header_color=245, header_bold=True),
    # Novelty color profiles
    'cupcake':ColorProfile(even_color=104, odd_color=164,
        header_color=104, header_bold=True,
        stale_emoji=emojize(':unicorn_face:'),
        snac_emojis=(False,emojize(':shortcake:'))),
    'poo':ColorProfile(even_color=136, odd_color=94,
            header_color=136, header_bold=True,
            stale_emoji=emojize(':pile_of_poo:')),
    'foxhound':ColorProfile(even_color=166, odd_color=179,
            header_color=166, header_bold=True,
            snac_emojis=(
                False,emojize(':cigarette:'),
                ),
            stale_emoji=emojize(':fox_face:')
            ),
    'rhino':ColorProfile(even_color=254, odd_color=244,
            header_color=254, header_bold=True,
            stale_emoji=emojize(':rhinoceros:')),
    'halloween':ColorProfile(even_color=166, odd_color=179,
            header_color=166, header_bold=True,
            snac_emojis=(
                False,emojize(':jack-o-lantern:'),
                ),
            stale_emoji=emojize(':ghost:')
            )
}
