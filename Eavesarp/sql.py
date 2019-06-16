#!/usr/bin/env python3

from sqlalchemy import (Column, Integer, String, DateTime, ForeignKey,
        func, text, ForeignKeyConstraint, UniqueConstraint,
        create_engine, asc, desc, Boolean)
from sqlalchemy.orm import (relationship, backref, sessionmaker,
        close_all_sessions)
from sqlalchemy.ext.declarative import declarative_base
from pathlib import Path
from os import remove

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
    mac_address = Column(String, nullable=True,
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
        if val.__class__ == str and self.value == val:
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

    Additional methods have been defined to facilitate extraction
    of data for table columns.
    '''

    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    sender_ip_id = Column(Integer,nullable=False)
    target_ip_id = Column(Integer,nullable=False)
    count = Column(Integer,default=1)
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

    def build_target(self,*args,**kwargs):
        return self.target.value

    def build_sender(self,*args,**kwargs):
        return self.sender.value

    def stale_target(self,display_false=True,*args,**kwargs):
        '''Return True if the target is stale, i.e. arp resolution
        has been attempted and no MAC address has been set.
        '''

        if self.target.arp_resolve_attempted and \
                not self.target.mac_address:
            return True
        else:
            if display_false:
                return False
            else:
                return ''

    def build_count(self,*args,**kwargs):
        '''Return the count of ARP requests as a string value.
        '''

        return str(self.count)

    def build_arp_count(self,*args,**kwargs):
        return self.build_count(*args,**kwargs)

    def build_stale(self,color_profile=None,display_false=True,
            *args,**kwargs):
        '''Build the value for the stale column. The character
        returned will be derived from the color_profile value.
        '''
    
        if not color_profile or not color_profile.stale_emoji:
            stale_char = True
        else:
            stale_char = color_profile.stale_emoji

        if self.stale_target():
            return stale_char
        elif not self.target.arp_resolve_attempted:
            return '[UNCONFIRMED]'
        else:
            if display_false:
                return False
            else:
                return ''

    def build_snac(self,color_profile=None,display_false=True,
            *args, **kwargs):

        has_snac = False
        for t in self.sender.sender_transactions:
            targ = t.target
            if targ.arp_resolve_attempted and not targ.mac_address:
                has_snac = True
                break

        return has_snac
    
    def build_target_mac(self,*args,**kwargs):
        '''Return the MAC address for the target:

        - [STALE TARGET] - returned when the target is stale
        - [UNRESOLVED] - indicates that no MAC is available 
        and ARP resolution has not been attempted.
        - MAC ADDRESS - when a MAC value is available for the IP
        '''
    
        if self.stale_target():
            return '[STALE TARGET]'
        elif self.target.mac_address:
            return self.target.mac_address
        elif not self.target.arp_resolve_attempted:
            return '[UNRESOLVED]'

    def build_sender_mac(self,new_sender=False,force_sender=False,
            *args,**kwargs):
        '''Return the MAC address for the sender of the
        transaction. Guaranteed to exist since it is associated
        with the sender itself.
        '''
        
        if new_sender or force_sender:
            return self.sender.mac_address
        else:
            return ''

    def build_sender_ptr(self,*args,new_sender=False,force_sender=False,
            display_false=False,**kwargs):
        '''Return the PTR value for the sender if available.
        '''

        sptr = ''
        if self.sender.ptr and (new_sender or force_sender):
            sptr = self.sender.ptr[0].value
        elif display_false: sptr = None

        return sptr

    def build_target_ptr(self,display_false=False,*args,**kwargs):
        '''Return the PTR value for the target if available.
        '''

        tptr = ''
        if self.target.ptr:
            tptr = self.target.ptr[0].value 
        elif display_false:
            tptr = None

        return tptr

    def build_target_forward(self,*args,**kwargs):
        '''Build the forward IP address for the PTR value of
        a given target address. This is useful when determining
        if a given target may have a MITM opportunity when the
        target address is stale.
        '''

        tptr = self.target.ptr[0] if self.target.ptr else None

        return tptr.forward_ip if tptr and tptr.forward_ip else ''
    
    def build_mitm_op(self,display_false=True,*args,**kwargs):
        '''Check the target of a transaction to determine
        if a potential MITM opportunity exists when a new
        forward address is available for a previous PTR
        address.
        '''
    
        if self.target.ptr:
    
            if self.stale_target() and self.target.ptr[0].forward_ip and \
                    self.target.ptr[0].forward_ip != self.target.value:
                return f'T-IP:{self.target.value} != ' \
                       f'PTR-FWD:{self.target.ptr[0].forward_ip}'
        
        if display_false:
            return False
        else:
            return ''

    def build_from_handle(self,handle,*args,**kwargs):
        '''Build a column value from attribute name.
        '''

        return self.__getattribute__(handle)(*args,**kwargs)

    bfh = build_from_handle

def create_db(dbfile,overwrite=False):
    '''Initialize the database file and return a session
    object.
    '''

    engine = create_engine(f'sqlite:///{dbfile}')
    Session = sessionmaker()
    Session.configure(bind=engine)

    pth = Path(dbfile)

    # Remove the file if specified
    if pth.exists() and overwrite:
        remove(pth)

    # Don't clobber pre-existing database files
    if not Path(dbfile).exists() or overwrite:
        Base.metadata.create_all(engine)

    return Session()

def get_transactions(db_session,order_by=desc):

    # Getting all transaction objects
    return db_session.query(Transaction) \
            .order_by(desc(Transaction.count)) \
            .all()

def get_or_create_ip(value, db_session, ptr=None, mac_address=None,
        arp_resolve_attempted=False, reverse_dns_attempted=False):
    '''Get or create an IP object from the SQLite database. Also
    handles:

    - Reverse Name Resolution
    - ARP resolution
    '''

    ip = db_session.query(IP).filter(IP.value==value).first()

    if not ip:

        ip = IP(value=value,mac_address=mac_address,)

        if mac_address or arp_resolve_attempted:
            ip.arp_resolve_attempted = True

        if reverse_dns_attempted:
            ip.reverse_dns_attempted = True

        db_session.add(ip)
        db_session.commit()

    elif ip and mac_address and ip.mac_address != mac_address:

        ip.mac_address = mac_address
        ip.arp_resolve_attempted = True
        db_session.commit()

    return ip

def get_or_create_ptr(value,ip_id,db_session,forward_ip=None):

    ptr = db_session.query(PTR).filter(PTR.value==value).first()

    if not ptr:

        ptr = PTR(value=value,ip_id=ip_id,forward_ip=forward_ip)

        db_session.add(ptr)
        db_session.commit()

    return ptr
