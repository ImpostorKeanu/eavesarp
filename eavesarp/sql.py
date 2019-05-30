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
        doc='''Determines if an ARP request has been made for this host
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
