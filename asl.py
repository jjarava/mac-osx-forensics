#!/usr/bin/python
# -*- coding: utf-8 -*-
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
""" Apple System Log Parser """

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

# README:
# The goal of this tools is only for developing purpose.
# The full documented and well implemented version is going to be in PLASO:
# https://code.google.com/p/plaso/
# http://plaso.kiddaland.net/


# Disclaimer: it only was probed in 10.8 and 10.9.

import construct
import os
import struct
import sys
import time

# Magic file number.
ASL_MAGIC = 'ASL DB\x00\x00\x00\x00\x00\x00'

# Priority levels.
ASL_MESSAGE_PRIORITY = {
    0 : 'EMERGENCY',
    1 : 'ALERT',
    2 : 'CRITICAL',
    3 : 'ERROR',
    4 : 'WARNING',
    5 : 'NOTICE',
    6 : 'INFO',
    7 : 'DEBUG'}

# ASL Required Structures.

# ASL header file structure
ASL_HEADER_STRUCT = construct.Struct(
    'asl_header_struct',
    construct.String('magic', 12),
    construct.UBInt32('version'),
    construct.UBInt64('offset'),
    construct.UBInt64('timestamp'),
    construct.UBInt32('cache_size'),
    construct.UBInt64('last_offset'),
    construct.Padding(36))

# Record = [Heap][Record_Struct][Values]
# Heap = [Group of Dyn_Value]*
# Values = [ADDR_TXT][ADDR_TXT][ADDR_TXT][ADDR_TXT](2x[ADDR_TXT])*
#            (Host)   (Sender) (Facility) (message)

# Record Struct
ASL_RECORD_STRUCT = construct.Struct(
    'asl_record_struct',
    construct.Padding(2),
    construct.UBInt32('tam_entry'),
    construct.UBInt64('next_offset'),
    construct.UBInt64('ASLMessageID'),
    construct.UBInt64('timestamp'),
    construct.UBInt32('nanosec'),
    construct.UBInt16('level'),
    construct.UBInt16('flags'),
    construct.UBInt32('pid'),
    construct.UBInt32('uid'),
    construct.UBInt32('gid'),
    construct.UBInt32('read_uid'),
    construct.UBInt32('read_gid'),
    construct.UBInt64('ref_pid'))

# Pointer Values
ASL_RECORD_ADDR_TXT = construct.Struct(
    'addr_or_text', construct.String('addr_txt', 8))

# Pointer Dynamic Value
ASL_RECORD_DYN_VALUE = construct.Struct(
    'asl_record_text_header',
    construct.Padding(2),
    construct.PascalString(
        'value', length_field = construct.UBInt32('length')))

# Print the header of the file
def printHeader(header): 
  print "\nASL Header:"
  print " Version: " + str(header.version)
  print " Timestamp: " + str(header.timestamp)
  print " FirstRecord: " + hex(header.offset)
  print " LastRecord: " + hex(header.last_offset) + "\n"

# Print a record value
#
# Args:
#  record_header: values from the Record_Struct part.
#  values: values from the bottom part (Values)
#  pos: where the Record_Structure starts in the file.
def printRecord(record_header, values, pos):
  # Static part of the entry
  human_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(record_header.timestamp))
  print '\t Record in: {}'.format(hex(pos))
  print '\t * Next record in: {}'.format(hex(record_header.next_offset))
  print '\t * ASLMessageID: {}'.format(record_header.ASLMessageID)
  print '\t * Timestamp: {0} ({1})'.format(human_time, record_header.timestamp)
  print '\t * Level: {0} ({1}), PID: {2}'.format(ASL_MESSAGE_PRIORITY[record_header.level],
      record_header.level, record_header.pid)
  fieldsID = ['UID: {}'.format(record_header.uid), 'GID: {}'.format(record_header.gid)]
  # If it is a valid read u/gid:
  if record_header.read_uid != int('ffffffff', 16):
    fieldsID.append('Read_UID: {}'.format(record_header.read_uid))
  if record_header.read_gid != int('ffffffff', 16):
    fieldsID.append('Read_GID: {}'.format(record_header.read_gid))
  print '\t * {}'.format(', '.join(fieldsID))

  # Dynamic part of the entry.
  # Host, Sender, Facility, Message, Name_Field1, Field1, Name_Field2, Field2, ...
  print '\t * Host: {0}'.format(values[0].partition('\x00')[0])
  print '\t * Sender: {0}'.format(values[1].partition('\x00')[0])
  print '\t * Facility: {0}'.format(values[2].partition('\x00')[0])
  print '\t * Message: {0}'.format(values[3].partition('\x00')[0])
  cont = 4
  while cont < (len(values) - 1):
      print '\t * {0}: {1}'.format(values[cont].partition('\x00')[0],
          values[cont+1].partition('\x00')[0])
      cont += 2
  print '\t------------------------------------------------------'

# Main program
def __init__():
  if len(sys.argv) != 2:
    print 'Use: python {0} ASLfile'.format(sys.argv[0])
    exit(1)
  log = sys.argv[1]
  try:
    f = open(log, 'rb')
  except:
    print '[Error] The file ASL does not exist'
    exit(1)

  print '\nParsing the ASL file [{}].'.format(log)

  try: 
    header = ASL_HEADER_STRUCT.parse_stream(f)
  except:
    print "[Error]It is not a ASL file, ASL Header not valid."
    exit(1)
  if header.magic != ASL_MAGIC:
    print "[Error]It is not a ASL file, ASL_MAGIC invalid."
    exit(1)
    
  printHeader(header)
  
  offset = header.offset
  last_offset = header.last_offset 
  last = False

  # Parsing the dynamic fields from the entry
  while offset <= last_offset and last == False:
    # The heap of the entry is saved to try to avoid seek (performance issue)
    dynamic_start = f.tell()
    dynamic_part = f.read(offset - f.tell())

    record_header = ASL_RECORD_STRUCT.parse_stream(f)
    
    # -2 -> + 6 - 8
    # +6 because the header already counts the padding + tam entry.
    # -8 because the last 8 byte register is a pointer to the previous entry.
    tam_entry = record_header.tam_entry - ASL_RECORD_STRUCT.sizeof() - 2

    # Dynamic part of the entry
    values = []
    read_value = 0
    while tam_entry > 0:
      #print tam_entry
      data = ASL_RECORD_ADDR_TXT.parse_stream(f)
      tam_entry -= 8
      # If not direction or data, jump to the next 8 bytes
      # HELP: exists another option better than need to use the encode('hex')??
      if data.addr_txt.encode('hex') != '0000000000000000':
        # If it is direction then jump, if it is not, then read the data
        if data.addr_txt.encode('hex')[0:1] != '8':
          # If the pointer points to the dynamic header of the entry
          pos = int(data.addr_txt.encode('hex'), 16) - dynamic_start
          if pos >= 0:
            values.append((ASL_RECORD_DYN_VALUE.parse(dynamic_part[pos:])).value)
          else:
            # Only if it is a pointer that points to the heap to another entry we use
            # the seek method, avoiding performance issues
            pos = f.tell()
            f.seek(int(data.addr_txt.encode('hex'), 16))
            values.append((ASL_RECORD_DYN_VALUE.parse_stream(f)).value)
            # Come back to the position in the entry
            f.seek(pos)
        else:
          values.append(data.addr_txt[1:])

    # Print the record
    printRecord(record_header, values, offset)

    #Read the last 8 bytes that points to the previous position
    f.read(8)

    # Last entry
    if record_header.next_offset < offset:
      last = True
    else:
      # Jump to the next entry
      offset = record_header.next_offset

__init__()
