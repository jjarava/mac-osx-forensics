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
""" Basic Security Module """

# Reference (A lot of fields are not exactly as the doc says)
# https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man5/audit.log.5.html

# MSc Project in Royal Holloway, University of London. 
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

# README:
# The goal of this tools is only for developing purpose.
# The full documented and well implemented version is going to be in PLASO:
# https://code.google.com/p/plaso/
# http://plaso.kiddaland.net/

# Disclaimer: it only was probed in 10.9.

# TODO: Not all the structures are implemented. If you find a non implemented structure, please report to
#       me the ID of the structure an a RAW example of this structure (copy 50 bytes from the address of
#       the structure. As an example, if the program tell you a [WARNING] providing an integer position
#       of the structure, you only need to calculate the size as a integer + 50 and then "xxd -l size file"

import construct
import os
import struct
import sys
import time

# Structure BSM, I have ommited the ID always. I use the BSM_TYPE first and then, the structure.

BSM_TYPE = construct.Struct(
    'type',
    construct.UBInt8('type'))

BSM_HEADER = construct.Struct(
    'header',
    construct.UBInt32('audit_id'),
    construct.UBInt8('version'),
    construct.UBInt16('event_type'),
    construct.UBInt16('modifier'),
    construct.UBInt32('timestamp'),
    construct.UBInt32('microsecond'))

BSM_TOKEN_TEXT = construct.Struct(
    'bsm_token_text',
    construct.PascalString(
        'value', length_field = construct.UBInt16('length')))

BSM_TOKEN_PATH = construct.Struct(
    'bsm_token_path',
    construct.PascalString(
        'value', length_field = construct.UBInt16('length')))

BSM_TOKEN_EXIT = construct.Struct(
    'bsm_token_exit',
    construct.UBInt16('process_exit'),
    construct.UBInt16('return_value'))
       
BSM_TOKEN_TRAILER = construct.Struct(
    'bsm_token_trailer',
     construct.UBInt8('trailer_magic_13'),
     construct.UBInt8('trailer_magic_b1'),
     construct.UBInt8('trailer_magic_05'),
     construct.UBInt32('record_lenght'))

BSM_TOKEN_ARGUMENT_32 = construct.Struct(
    'bsm_token_argument',
    construct.UBInt8('num_arg'),
    construct.UBInt32('value'),
    construct.PascalString(
        'value_txt', length_field = construct.UBInt16('length')))
        
BSM_TOKEN_ARGUMENT_64 = construct.Struct(
    'bsm_token_argument',
    construct.UBInt8('num_arg'),
    construct.UBInt64('value'),
    construct.PascalString(
        'value_txt', length_field = construct.UBInt16('length')))

BSM_TOKEN_SUBJECT = construct.Struct(
    'bsm_token_subject',
    construct.UBInt32('audit_uid'),
    construct.UBInt32('effective_uid'),
    construct.UBInt32('effective_gid'),
    construct.UBInt32('real_uid'),
    construct.UBInt32('real_gid'),
    construct.UBInt32('pid'),
    construct.UBInt32('session_id'),
    construct.UBInt32('terminal_id'),
    construct.UBInt32('terminal_addr'))

# TODO: This structure is not properly parsed.
BSM_TOKEN_SUBJECT_EX = construct.Struct(
    'bsm_token_subject_ex',
    construct.UBInt32('audit_uid'),
    construct.UBInt32('effective_uid'),
    construct.UBInt32('effective_gid'),
    construct.UBInt32('real_uid'),
    construct.UBInt32('real_gid'),
    construct.UBInt32('pid'),
    construct.UBInt32('session_id'),
    construct.UBInt32('terminal_id'),
    construct.UBInt32('unknown'),
    construct.UBInt32('terminal_addr'))

# List of valid Token_ID
# Token_ID -> [NAME_STRUCTURE, STRUCTURE]
'''  
BSM_HEADER == 20 (0x14)
BSM_TOKEN_TRAILER == 00 (0x00)
BSM_TOKEN_PATH  == 35 (0x23)
BSM_TOKEN_SUBJECT == 36 (0x24)
BSM_TOKEN_EXIT == 39 (0x27)
BSM_TOKEN_TEXT == 40 (0x28)
BSM_TOKEN_ARGUMENT_32 == 45 (0x2d)
BSM_TOKEN_ARGUMENT_64 == 113 (0x71)
BSM_TOKEN_SUBJECT_EX == 122 (0x7a)
'''
BSM_TYPE_LIST = {
0 : ['BSM_TOKEN_TRAILER', BSM_TOKEN_TRAILER],
20 : ['BSM_HEADER', BSM_HEADER],
35 : ['BSM_TOKEN_PATH', BSM_TOKEN_PATH],
36 : ['BSM_TOKEN_SUBJECT', BSM_TOKEN_SUBJECT],
39 : ['BSM_TOKEN_EXIT', BSM_TOKEN_EXIT],
40 : ['BSM_TOKEN_TEXT', BSM_TOKEN_TEXT],
45 : ['BSM_TOKEN_ARGUMENT_32', BSM_TOKEN_ARGUMENT_32],
113 : ['BSM_TOKEN_ARGUMENT_64', BSM_TOKEN_ARGUMENT_64],
122 : ['BSM_TOKEN_SUBJECT_EX', BSM_TOKEN_SUBJECT_EX]}

# Format a Token to be printed.
#
# Args:
#   id: text name that identificate the Token ID
#   token: the token structure  to be formated.
#
# Return:
#   A list with a well formated Token.
def FormatToken(id, token):
  elem = []
  if id == 'BSM_HEADER':
    elem.append('\t* ID: {}'.format(token.audit_id))
    elem.append('\t* Type (audit_event): {}'.format(token.event_type))
    elem.append('\t* Modifier: {}'.format(token.modifier))
    elem.append('\t* Time: {2} ({0}.{1})'.format(token.timestamp, token.microsecond, time.strftime(
        '%Y-%m-%d %H:%M:%S', time.gmtime(token.timestamp))))
  elif id == 'BSM_TOKEN_EXIT':
    elem.append('\t* Exit {0}, return value {1}'.format(
        token.process_exit, token.return_value))
  elif id == 'BSM_TOKEN_TRAILER':
    elem.append('\t* Trailer: {}'.format(token.record_lenght))
    elem.append('\t-------------------------------')
  elif id == 'BSM_TOKEN_TEXT':
      elem.append('\t* Text: {}'.format(token.value[:-1]))
  elif id == 'BSM_TOKEN_PATH':
    elem.append('\t* Path: {}'.format(token.value))
  elif id == 'BSM_TOKEN_SUBJECT' or id == 'BSM_TOKEN_SUBJECT_EX':
    elem.append('\t* Subject: aid({}), euid({}), egid({}), uid({}), gid({}), pid({}), session_id({})'.format(
        token.audit_uid, token.effective_uid, token.effective_gid, token.real_uid, token.real_gid,
        token.pid, token.session_id)) 
  elif id == 'BSM_TOKEN_ARGUMENT_32' or id == 'BSM_TOKEN_ARGUMENT_64':
    elem.append('\t* Argument {0}({1}) is {2}'.format(
        token.value_txt[:-1], token.num_arg, hex(token.value)))
  else:
    elem.append('\t* Type Unknown: {0} ({1})'.format(id, hex(id)))
  return elem

# Checks if the ID is a valid ID.
# If it not a valid ID (Unknown structure) looks for the end of the event to parse the next one.
# The event without unknown structure is not parsed.
#
# Args:
#   f : BSM file.
#   type: Token ID that we want to check.
def CheckTokenId(f, type):
  # If the ID is Unknown
  if type not in BSM_TYPE_LIST:
    print '[WARNING] The data at "{0}({1})" cannot be parse:'.format(f.tell(), hex(f.tell()))
    print '\t  Unknown Token ID: {0} ({1}). token lost.'.format(type, hex(type))
    # Trying to jump to the next token
    # Read until find the Token ID of the exit
    try:
      valid_exit = False
      while(valid_exit == False):
        # Try from the type equal than BSM_TOKEN_EXIT and check until find a real
        # BSM_TOKEN_EXIT
        exit = False
        while(not exit):
          # Until find a valid Token ID
          type = BSM_TYPE.parse_stream(f).type
          while(type not in BSM_TYPE_LIST): 
            type = BSM_TYPE.parse_stream(f).type
          # A ID with the same value than BSM_TOKEN_EXIT was found.
          if BSM_TYPE_LIST[type][0] == 'BSM_TOKEN_EXIT':
            exit = True   
        # Save the actual position
        pos = f.tell()
        # The end of the token might be found.
        _ = BSM_TOKEN_EXIT.parse_stream(f)
        # If the ID is not a Trailer it was not TOKEN_EXIT.
        type = BSM_TYPE.parse_stream(f).type
        if ((type not in BSM_TYPE_LIST) or 
            (BSM_TYPE_LIST[type][0] != 'BSM_TOKEN_TRAILER')):
          f.seek(pos)
        else:
          # The magic need to be 13 b1 and 05, if not, we are not in Trailer.
          data = BSM_TOKEN_TRAILER.parse_stream(f) 
          if (data.trailer_magic_13 != int('13',16) or
              data.trailer_magic_b1 != int('b1',16) or
              data.trailer_magic_05 != int('5',16)):
            f.seek(pos)
          else:
            valid_exit = True
    except IOError:
      sys.exit(1)
    except:
      print '[ERROR] The token cannot be jumped, FINISHING!!!'
      sys.exit(1)
    return None
  return True 

# Read one BSM Event
# Args:
#   f : BSM file.
#   event_number: the number of the event.
def ReadBSMEvent(f, event_number):
    data = []
    token = BSM_HEADER.parse_stream(f)
    data = FormatToken('BSM_HEADER', token)
    type = BSM_TYPE.parse_stream(f).type
    if not CheckTokenId(f, type):
      return 
    while BSM_TYPE_LIST[type][0] != 'BSM_TOKEN_EXIT':
      token = BSM_TYPE_LIST[type][1].parse_stream(f)
      data += FormatToken(BSM_TYPE_LIST[type][0], token)
      type = BSM_TYPE.parse_stream(f).type
      if not CheckTokenId(f, type):
        return 
    token = BSM_TOKEN_EXIT.parse_stream(f)
    data += FormatToken('BSM_TOKEN_EXIT', token)
    _ = BSM_TYPE.parse_stream(f).type
    token = BSM_TOKEN_TRAILER.parse_stream(f)
    data += FormatToken('BSM_TOKEN_TRAILER', token)
    print '\tEvent: {}'.format(event_number)
    print '\n'.join(data)

# Check if the file is a BSM file.
#
# Args:
#   f : file that we want to check.
def VerifyFile(f):
  type = BSM_TYPE.parse_stream(f).type
  if BSM_TYPE_LIST[type][0] != 'BSM_HEADER':
    print '[Error] It is not a BSM file'
    exit(1) 
  try: 
    header = BSM_HEADER.parse_stream(f)
  except:
    print '[Error] It is not a BSM file'
    exit(1)
  f.close()

# Main function.
def __init__():
  if len(sys.argv) != 2:
    print 'Use: python {0} BSMfile'.format(sys.argv[0])
    exit(1)
  log = sys.argv[1]
  try:
    f = open(log, 'rb')
  except:
    print '[Error] The file BSM does not exist'
    exit(1)
    
  VerifyFile(f)
  print '\nParsing BSM file [{}].\n'.format(log)

  f = open(log, "rb")
  event_number = 0
  data = BSM_TYPE.parse_stream(f)
  while data:
    event_number += 1
    ReadBSMEvent(f, event_number)
    try:
      data = BSM_TYPE.parse_stream(f)
    except:
      data = None
  f.close() 
    

__init__()

