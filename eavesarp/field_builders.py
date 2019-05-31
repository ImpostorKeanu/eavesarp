#!/usr/bin/env python3

def build_stale(t,color_profile=None):

    if not color_profile or not color_profile.stale_emoji:
        stale_char = 'X'
    else:
        stale_char = color_profile.stale_emoji

    if t.stale_target:
        return stale_char
    else:
        return ''

def build_target_mac(t):

    if t.stale_target:
        return '[STALE TARGET]'
    elif t.target.mac_address:
        return t.target.mac_address
    else:
        return '[UNRESOLVED]'

def build_reverse_resolve(t):
    '''Build the DNS reverse resolution fields for the
    Sender PTR, Target PTR, and Target IP != Forward IP
    columns.

    returns a tuple: (sender_pointer,target_pointer,)
    '''

    sptr = build_ptr_string(t.sender)
    tptr = build_ptr_string(t.target)
    
    return sptr,tptr

def build_mitm_op(t):

    if t.target.ptr:
        if t.target.ptr[0].forward_ip != t.target.value:
            return True
    else: return False

def build_ptr_string(ip):

    if ip.ptr:
        ptr = ip.ptr[0].value
        fwd = ip.ptr[0].forward_ip
        if fwd:
            return f'{ptr} ({fwd})'
        else:
            return ptr
    
    return ''
