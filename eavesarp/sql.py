#!/usr/bin/env python3

from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey,
        func, text, ForeignKeyConstraint, UniqueConstraint,
        create_engine, asc, desc, Boolean)
from sqlalchemy.orm import (relationship, backref, sessionmaker,
        close_all_sessions)
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()
class IP(Base):
    '''IP model.
    '''

    __tablename__ = 'ip'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False, unique=True,
            doc='IP address value')
    ptr = relationship('PTR', back_populates='ip')
    arp_resolve_attempted = Column(Boolean, nullable=False, default=False,
        doc='''Determines if an ARP request has been made for this host
        ''')
    reverse_dns_attempted = Column(Boolean, nullable=False, default=False,
        doc='''Determines if reverse dns has been made for this host
        ''')
    mac_address = Column(String, nullable=True, unique=True,
        doc='''The MAC address obtained via ARP request.
        ''')
    sender_transactions = relationship('Transaction',
          back_populates='sender',
          primaryjoin='and_(Transaction.sender_ip_id==IP.id)')
    target_transactions = relationship('Transaction',
          back_populates='target',
          primaryjoin='and_(Transaction.target_ip_id==IP.id)')

    def __eq__(self,val):
        '''Override to allow string comparison.
        '''

        if klass == str and self.value == val:
            return True

        super().__eq__(val)

class PTR(Base):
    '''PTR model.
    '''

    __tablename__ = 'ptr'
    id = Column(Integer, primary_key=True)
    ip_id = Column(Integer, ForeignKey(IP.id), nullable=False,unique=True)
    ip = relationship('IP', back_populates='ptr')
    forward_ip = Column(String, nullable=True,
        doc='''Forward IP resolved from reverse IP.
        ''')
    value = Column(String, nullable=False, unique=True,
            doc='PTR value')

class Transaction(Base):
    '''Transaction model.
    '''

    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    sender_ip_id = Column(Integer,nullable=False)
    target_ip_id = Column(Integer,nullable=False)
    count = Column(Integer,default=1)
    stale_target = Column(Boolean, nullable=False, default=False,
        doc='''Determines if a given target is stale
        ''')
    sender = relationship('IP',
         back_populates='sender_transactions',
         primaryjoin='and_(Transaction.sender_ip_id==IP.id)')
    target = relationship('IP',
         back_populates='target_transactions',
         primaryjoin='and_(Transaction.target_ip_id==IP.id)')
    ForeignKeyConstraint(
        [sender_ip_id,target_ip_id],
        [IP.id,IP.id],
    )

    def build_count(self,*args,**kwargs):

        return str(self.count)

    def build_stale(self,color_profile=None,*args,**kwargs):
    
        if not color_profile or not color_profile.stale_emoji:
            stale_char = 'X'
        else:
            stale_char = color_profile.stale_emoji
    
        if self.stale_target:
            return stale_char
        else:
            return ''
    
    def build_target_mac(self,*args,**kwargs):
    
        if self.stale_target:
            return '[STALE TARGET]'
        elif self.target.mac_address:
            return self.target.mac_address
        else:
            return '[UNRESOLVED]'

    def build_sender_mac(self,*args,**kwargs):

        return self.sender.mac_address
    
    def build_reverse_resolve(self,*args,**kwargs):
        '''Build the DNS reverse resolution fields for the
        Sender PTR, Target PTR, and Target IP != Forward IP
        columns.
    
        returns a tuple: (sender_pointer,target_pointer,)
        '''
    
        sptr = self.build_ptr_string(self.sender)
        tptr = self.build_ptr_string(self.target)
        
        return sptr,tptr

    def build_sender_ptr(self,*args,new_sender=False,**kwargs):

        if new_sender:
            return self.build_ptr_string(self.sender)
        else:
            return ''

    def build_target_ptr(self,*args,**kwargs):

        return self.build_ptr_string(self.target)
    
    def build_mitm_op(self,*args,**kwargs):
        '''Check the target of a transaction to determine
        if a potential MITM opportunity exists when a new
        forward address is available for a previous PTR
        address.
        '''
    
        if self.target.ptr:
    
            if self.target.ptr[0].forward_ip != self.target.value:
                return True
        
        return False
    
    def build_ptr_string(self,ip,*args,**kwargs):
    
        if ip.ptr:
            ptr = ip.ptr[0].value
            fwd = ip.ptr[0].forward_ip
            if fwd:
                return f'{ptr} ({fwd})'
            else:
                return ptr
        
        return ''

    def build_from_handle(self,handle,*args,**kwargs):

        return self.__getattribute__(handle)(*args,**kwargs)

    bfh = build_from_handle
