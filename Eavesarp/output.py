#!/usr/bin/env python3

from Eavesarp.lists import *
from Eavesarp.sql import *
from Eavesarp.misc import get_interfaces
from tabulate import tabulate
from io import StringIO
import csv

# ===================
# CONSTANTS/FUNCTIONS
# ===================

COL_MAP = {
    'arp_count':'ARP#',
    'sender':'Sender',
    'sender_mac':'Sender MAC',
    'target':'Target',
    'target_mac':'Target MAC',
    'stale':'Stale',
    'sender_ptr':'Sender PTR',
    'target_ptr':'Target PTR',
    'target_forward':'Target PTR Forward',
    'mitm_op':'MITM',
    'snac':'SNAC',
}

COL_ORDER = [
    'snac',
    'sender',
    'target',
    'arp_count',
    'stale'
]

def validate_columns(output_columns):

    vals = COL_MAP.keys()
    bad = [v for v in output_columns if not v in vals]

    if bad:

        print('- Invalid column values provided: ',','.join(bad))
        print('- Valid values: ',','.join(vals))
        print('Exiting!')
        exit()

    return

def get_interface_table(require_ip=False):
    
    rows = [
            [iface,t[0],'\n'.join(t[1])] for iface,t in
            get_interfaces(require_ip).items()
    ]
    

    return tabulate(
        rows,
        ['Interface','MAC','IP Addresses']
    )


def get_output_csv(db_session,order_by=desc,sender_lists=None,
        target_lists=None):

    # ==========================
    # HANDLE SENDER/TARGET LISTS
    # ==========================
    
    sender_lists = sender_lists or Lists()
    target_lists = target_lists or Lists()

    # ===============
    # PREPARE COLUMNS
    # ===============

    columns = list(COL_MAP.keys())

    # ====================
    # GET ALL TRANSACTIONS
    # ====================

    transactions = get_transactions(db_session,order_by)

    # =============================
    # WRITE CSVS TO STRINGIO OBJECT
    # =============================

    outfile = StringIO()
    writer = csv.writer(outfile)
    writer.writerow(columns)

    #if 'snac' in columns: snacs = get_snacs(db_session)
    #else: snacs = []

    # Write all transactions
    for t in transactions:

        writer.writerow(
            [t.bfh('build_'+col,new_sender=True,display_false=True) for col in columns]
        )

    outfile.seek(0)

    # Return the output
    return outfile

def get_stale_ips(db_session):
    '''Return a list of IP objects that are known to be SNACs.
    '''

    snacs = []

    # Build the list of snacs
    snacs = db_session.query(IP) \
        .filter(IP.arp_resolve_attempted==True) \
        .filter(IP.mac_address==None) \
        .all()

    return snacs

def build_snac(target,stale_ips,color_profile,display_false=True):
    '''Build the SNAC value for a given sender.
    '''

    snac = (False,True)[target in stale_ips]

    # Handle color profile
    if color_profile and color_profile.snac_emojis:

        # When the snac is valid or false should be
        # displayed
        if snac or not snac and display_false:
            snac = color_profile.snac_emojis[snac]
        elif display_false:
            pass
        else:
            snac = ''

    # When the sender isn't a snac
    elif not snac and not display_false:
        snac = ''

    return snac

def get_output_table(db_session,order_by=desc,sender_lists=None,
        target_lists=None,color_profile=None,dns_resolve=True,
        arp_resolve=False,columns=COL_ORDER,display_false=False,
        force_sender=False,stale_only=False):
    '''Extract transaction records from the database and return
    them formatted as a table.
    '''

    sender_lists = sender_lists or Lists()
    target_lists = target_lists or Lists()

    transactions = get_transactions(db_session,order_by)

    if not transactions:
        output = '- No accepted ARP requests captured\n' \
        '- If this is unexpected, check your whitelist/blacklist configuration'
        return output

    # ==============================
    # ADD A SNAC COLUMN IF REQUESTED
    # ==============================

    '''
    A host has a SNAC when it has no mac_address but has been
    targeted for ARP resolution. Since an IP object is generic,
    there is no attribute for 'stale' or 'snac', so a snac
    state must be inferred on the 'no mac and arp resolved' op.

    1. build a list of ip addresses that have no mac and have 
    been arp resolved
    2. as we build each table, check to see if the sender ip
    is in the list of stale. if so and this is the first time
    a sender has been added to the table, then populate the
    cell with a value of True, False, or and emoji.
    '''

    if 'snac' in columns: stale = get_stale_ips(db_session)
    else: stale = []

    # =====================================================
    # ADD PTR/STALE COLUMNS WHEN ARP/DNS RESOLVE IS ENABLED
    # =====================================================

    if arp_resolve and not 'stale' in columns \
            and columns == COL_ORDER:
        columns.append('stale')

    if dns_resolve and columns == COL_ORDER:
        if not 'sender_ptr' in columns:
            columns.append('sender_ptr')
        if not 'target_ptr' in columns:
            columns.append('target_ptr')
        if not 'mitm_op' in columns:
            columns.append('mitm_op')

    # Organize all the records by sender IP
    rowdict = {}
    for t in transactions:

        if stale_only and not t.stale_target():
            continue

        smac = t.sender.mac_address

        sender = t.sender.value
        target = t.target.value

        # ====================
        # FILTER BY IP ADDRESS
        # ====================

        if not filter_lists(sender_lists,target_lists,sender,target):
            continue

        # Flag to determine if the sender is new
        if sender not in rowdict: new_sender = True
        else: new_sender = False

        row = []

        for col in columns:

            if col == 'snac':

                if new_sender or force_sender:
                
                    row.append(
                        build_snac(t.target,stale,color_profile,
                            display_false)
                    )

                else:

                    row.append('')

            elif col == 'sender':

                if new_sender or force_sender: row.append(sender)
                else: row.append('')

            elif col == 'target':

                row.append(target)

            elif col == 'stale':

                row.append(t.build_stale(color_profile,
                    display_false=display_false))

            else:

                if col == 'arp_count': col = 'count'

                row.append(
                    t.bfh('build_'+col,new_sender=new_sender,
                        display_false=display_false,
                        force_sender=force_sender)
                )

        if new_sender: rowdict[sender] = [row]
        else: rowdict[sender].append(row)

    # Restructure dictionary into a list of rows
    rows = []
    counter = 0

    for sender,irows in rowdict.items():
        counter += 1

        # Color odd rows slightly darker
        if color_profile:

            if counter % 2:
                rows += [color_profile.style_odd([v for v in r]) for r in irows]
            else:
                rows += [color_profile.style_even(r) for r in irows]

        # Just add the rows otherwise
        else: rows += irows

    headers = [COL_MAP[col] for col in columns]

    # Color the headers
    if color_profile: headers = color_profile.style_header(headers)

    # Return the output as a table
    return tabulate(
            rows,
            headers=headers)
