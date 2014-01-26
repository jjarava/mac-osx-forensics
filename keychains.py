#!/usr/python
# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Cups Reading Control Files."""

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'


import construct
import datetime
import os
import sys

KEYCHAIN_MAGIC_HEADER = 'kych'
KEYCHAIN_MAJOR_VERSION = 1
KEYCHAIN_MINOR_VERSION = 0

# DB HEADER
KEYCHAIN_DB_HEADER = construct.Struct(
    'db_header',
    construct.String('magic', 4),
    construct.UBInt16('major_version'),
    construct.UBInt16('minor_version'),
    construct.UBInt32('header_size'),
    construct.UBInt32('schema_offset'),
    construct.Padding(4))
    
# DB SCHEMA    
KEYCHAIN_DB_SCHEMA = construct.Struct(
    'db_schema',
    construct.UBInt32('size'),
    construct.UBInt32('number_of_tables'))
# For each umber_of_tables, the schema has a TABLE_OFFSET with the
# offset starting in the DB_SCHEMA.
TABLE_OFFSET = construct.UBInt32('table_offset')

# TABLE
TABLE_RECORD_TYPE = {
    0: u'Schema information',
    1: u'Schema indexes',
    2: u'Schema attributes',
    3: u'Schema parsing module',
    10: u'Temporary table type',
    11: u'Certificates',
    12: u'Certificate Revocation List',
    13: u'Policy',
    14: u'Generic information',
    15: u'Public key',
    16: u'Private key',
    17: u'Symmetric key',
    18: u'Temporal table',
    2147483648: u'Application password',
    2147483649: u'Internet password',
    2147483650: u'Apple share password',
    2147483651: u'User X509 certificate',
    2147483652: u'X509 revocate list',
    2147483653: u'Unlock referral',
    2147483654: u'Extended attribute',
    2147487744: u'X509 Certificates',
    2147516416: u'Metadata information'}
    
TABLE_HEADER = construct.Struct(
    'table_header',
    construct.UBInt32('table_size'),
    construct.UBInt32('record_type'),
    construct.UBInt32('number_of_records'),
    construct.UBInt32('first_record'),
    construct.UBInt32('index_offset'),
    construct.Padding(4),
    construct.UBInt32('recordnumbercount'))
        
# RECORD         
TEXT = construct.PascalString(
    'text', length_field = construct.UBInt32('length'))   
TIME = construct.Struct(
    'timestamp',
    construct.String('year', 4),
    construct.String('month', 2),
    construct.String('day', 2),
    construct.String('hour', 2),
    construct.String('minute', 2),
    construct.String('second', 2),
   construct.Padding(2)) 
TYPE_TEXT = construct.String('type', 4)
RECORD_HEADER = construct.Struct(
    'record_entry',
    construct.UBInt32('entry_length'),
    construct.Padding(12),
    construct.UBInt32('ssgp_length'),
    construct.Padding(4),
    construct.UBInt32('creation_time'),
    construct.UBInt32('last_mod_time'),
    construct.UBInt32('text_description'),
    construct.Padding(16),
    construct.UBInt32('entry_name'),
    construct.Padding(20),
    construct.UBInt32('account_name'),
    construct.Padding(4),
    construct.UBInt32('where'),
    construct.UBInt32('protocol'),
    construct.UBInt32('type'),
    construct.Padding(4),
    construct.UBInt32('url'))

# IPython.embed()
f = open(sys.argv[1], 'rb')

db_header = KEYCHAIN_DB_HEADER.parse_stream(f)
if (db_header.minor_version != KEYCHAIN_MINOR_VERSION or
    db_header.major_version != KEYCHAIN_MAJOR_VERSION or
    db_header.magic != KEYCHAIN_MAGIC_HEADER):
    print u'It is not a valid Keychain file'
    exit(1)
      
# From the schema we get the number of tables and where these tables are.      
db_schema = KEYCHAIN_DB_SCHEMA.parse_stream(f)
table_offsets = []
print u'Number of tables: {}.'.format(db_schema.number_of_tables)
for i in range(db_schema.number_of_tables):
  table_offsets.append(TABLE_OFFSET.parse_stream(f) + KEYCHAIN_DB_HEADER.sizeof())


for table_offset in table_offsets:
  print u'Table at {0}(0x{0:x})'.format(table_offset)
  f.seek(table_offset)
  table = TABLE_HEADER.parse_stream(f)
  
  '''
  # Application
  if table.record_type == 2147483648: 
    print u'\tRecord type: {}'.format(TABLE_RECORD_TYPE[table.record_type])
    print u'\tSize: {}'.format(table.table_size)
    print u'\tNumber of records: {}'.format(table.number_of_records)
    print u'\tNumber of records count: {}'.format(table.recordnumbercount)
    print u'\tFirst record: {0}(0x{0:x}) = {1}'.format(
        table.first_record, table_offset + table.first_record)
    print u'\tFirst record index: {0}(0x{0:x}) = {1}'.format(
        table.index_offset, table_offset + table.index_offset)
  '''      
  
  if table.record_type == 2147483648 or table.record_type == 2147483649: 
    print u'\tRecord type: {}'.format(TABLE_RECORD_TYPE[table.record_type])
    print u'\tSize: {}'.format(table.table_size)
    print u'\tNumber of records: {}'.format(table.number_of_records)
    print u'\tNumber of records count: {}'.format(table.recordnumbercount)
    print u'\tFirst record: {0}(0x{0:x}) = {1}'.format(
        table.first_record, table_offset + table.first_record)
    print u'\tFirst record index: {0}(0x{0:x}) = {1}'.format(
        table.index_offset, table_offset + table.index_offset)
        
    f.seek(table_offset + table.first_record)
    for i in range(table.number_of_records):
      offset = f.tell()
      print u'\t\tRecord at: {0}(0x{0:x})'.format(offset)
      record = RECORD_HEADER.parse_stream(f)
      
      # Timestamps
      jump = record.creation_time - RECORD_HEADER.sizeof() - 1 
      f.seek(jump, os.SEEK_CUR)
      creation_time = TIME.parse_stream(f)
      print u'\t\tCreation time: {}-{}-{} {}:{}:{}'.format(
          creation_time.year, creation_time.month, creation_time.day, 
          creation_time.hour, creation_time.minute, creation_time.second)
          
      jump = record.last_mod_time - (f.tell() - offset) - 1  
      last_mod_time = TIME.parse_stream(f)
      print u'\t\tLast Modification time: {}-{}-{} {}:{}:{}'.format(
          last_mod_time.year, last_mod_time.month, last_mod_time.day, 
          last_mod_time.hour, last_mod_time.minute, last_mod_time.second)
          
      # Description name
      if record.text_description:    
        jump = record.text_description - (f.tell() - offset) - 1    
        f.seek(jump, os.SEEK_CUR) 
        text_description = TEXT.parse_stream(f)
        print u'\t\tDescription: {}'.format(text_description)
                
      # Name    
      jump = record.entry_name - (f.tell() - offset) - 1    
      f.seek(jump, os.SEEK_CUR) 
      entry_name = TEXT.parse_stream(f)
      print u'\t\tName: {}'.format(entry_name)
      
      # Account
      jump = record.account_name - (f.tell() - offset) - 1 
      f.seek(jump, os.SEEK_CUR)   
      account_name = TEXT.parse_stream(f)
      print u'\t\tAccount: {}'.format(account_name)
      
      # Where
      if record.where:
        jump = record.where - (f.tell() - offset) - 1
        f.seek(jump, os.SEEK_CUR)    
        where = TEXT.parse_stream(f)
        jump = record.protocol - (f.tell() - offset) - 1 
        f.seek(jump, os.SEEK_CUR)   
        protocol = TYPE_TEXT.parse_stream(f)
        jump = record.type - (f.tell() - offset) - 1 
        f.seek(jump, os.SEEK_CUR)   
        type = TEXT.parse_stream(f) 
        jump = record.url - (f.tell() - offset) - 1 
        f.seek(jump, os.SEEK_CUR)   
        url = TEXT.parse_stream(f)
        print u'\t\tWhere: {}{} ({}, {})'.format(where, url, protocol, type)
          
      f.seek(record.entry_length + offset)
      print "\t\t------------------------"
  
  
  
  
  
  