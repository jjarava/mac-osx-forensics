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
# The goal of this tools is only for developing pourpose.
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

##### CONSTANT #####

# BSM supported version (0x0b = 11)
AUDIT_HEADER_VERSION = 11

# Magic Trail Header
BSM_TOKEN_TRAILER_MAGIC = 'b105'

# File that translate the numeric type in text type
BSM_AUDIT_EVENT_FILE = '/etc/security/audit_event'

# Numeric ERRORS representation, read it in OpenBSM project: "audit_errno.h".
# TODO: I have been checked some of them against Mac OSX and I am changing
#       the name to be more clossed to Mac OS X and be more understandable.
BSM_ERRORS = {
    0 : 'SUCCESS',
    1 : 'OPERATION_NOT_PERMITTED',
    2 : 'NOENT',
    3 : 'SRCH',
    4 : 'INTR',
    5 : 'IO',
    6 : 'NXIO',
    7 : '2BIG',
    8 : 'NOEXEC',
    9 : 'BADF',
    10 : 'CHILD',
    11 : 'AGAIN',
    12 : 'NOMEM',
    13 : 'ACCES',
    14 : 'FAULT',
    15 : 'NOTBLK',
    16 : 'BUSY',
    17 : 'EXIST',
    18 : 'XDEV',
    19 : 'NODEV',
    20 : 'NOTDIR',
    21 : 'ISDIR',
    22 : 'INVAL',
    23 : 'NFILE',
    24 : 'MFILE',
    25 : 'NOTTY',
    26 : 'TXTBSY',
    27 : 'FBIG',
    28 : 'NOSPC',
    29 : 'SPIPE',
    30 : 'ROFS	',
    31 : 'MLINK',
    32 : 'PIPE',
    33 : 'DOM',
    34 : 'RANGE',
    35 : 'NOMSG',
    36 : 'IDRM',
    45 : 'DEADLK',
    46 : 'NOLCK',
    47 : 'CANCELED',
    48 : 'NOTSUP',
    49 : 'DQUOT',
    66 : 'REMOTE',
    67 : 'NOLINK',
    71 : 'PROTO',
    74 : 'MULTIHOP',
    77 : 'BADMSG',
    78 : 'NAMETOOLONG',
    79 : 'OVERFLOW',
    88 : 'ILSEQ',
    89 : 'NOSYS',
    90 : 'LOOP',
    91 : 'RESTART',
    93 : 'NOTEMPTY',
    94 : 'USERS',
    95 : 'NOTSOCK',
    96 : 'DESTADDRREQ',
    97 : 'MSGSIZE',
    98 : 'PROTOTYPE',
    99 : 'NOPROTOOPT',
    120 : 'PROTONOSUPPORT',
    121 : 'SOCKTNOSUPPORT',
    122 : 'OPNOTSUPP',
    123 : 'PFNOSUPPORT',
    124 : 'AFNOSUPPORT',
    125 : 'ADDRINUSE',
    126 : 'ADDRNOTAVAIL',
    127 : 'NETDOWN',
    128 : 'NETUNREACH',
    129 : 'NETRESET',
    130 : 'CONNABORTED',
    131 : 'CONNRESET',
    132 : 'NOBUFS',
    133 : 'ISCONN',
    134 : 'NOTCONN',
    143 : 'SHUTDOWN',
    144 : 'TOOMANYREFS',
    145 : 'TIMEDOUT',
    146 : 'CONNREFUSED',
    147 : 'HOSTDOWN',
    148 : 'HOSTUNREAC',
    149 : 'ALREADY',
    150 : 'INPROGRESS',
    151 : 'STALE',
    190 : 'PROCLIM',
    191 : 'BADRPC',
    192 : 'RPCMISMATCH',
    193 : 'PROGUNAVAIL',
    194 : 'PROGMISMATCH',
    195 : 'PROCUNAVAIL',
    196 : 'FTYPE',
    197 : 'AUTH',
    198 : 'NEEDAUTH',
    199 : 'NOATTR',
    200 : 'DOOFUS',
    201 : 'USTRETURN',
    202 : 'NOIOCTL',
    203 : 'DIRIOCTL',
    204 : 'PWROFF',
    205 : 'DEVERR',
    206 : 'BADEXEC',
    207 : 'BADARCH',
    208 : 'SHLIBVERS',
    209 : 'BADMACHO',
    210 : 'POLICY'}

# Numeric PROTOCOLS representation, read in OpenBSM project: "audit_fcntl.h".
# TODO: not checked
BSM_PROTOCOLS = {
    0 : 'UNSPEC',
    1 : 'LOCAL',
    2 : 'INET',
    3 : 'IMPLINK',
    4 : 'PUP',
    5 : 'CHAOS',
    6 : 'NS',
    8 : 'ECMA',
    9 : 'DATAKIT',
    10 : 'CCITT',
    11 : 'SNA',
    12 : 'DECnet',
    13 : 'DLI',
    14 : 'LAT',
    15 : 'HYLINK',
    16 : 'APPLETALK',
    19 : 'OSI',
    23 : 'IPX',
    24 : 'ROUTE',
    25 : 'LINK',
    26 : 'INET6',
    27 : 'KEY',
    500 : 'NETBIOS',
    501 : 'ISO',
    502 : 'XTP',
    503 : 'COIP',
    504 : 'CNT',
    505 : 'RTIP',
    506 : 'SIP',
    507 : 'PIP',
    508 : 'ISDN',
    509 : 'E164',
    510 : 'NATM',
    511 : 'ATM',
    512 : 'NETGRAPH',
    513 : 'SLOW',
    514 : 'CLUSTER',
    515 : 'ARP',
    516 : 'BLUETOOTH'}

# Text representation of the audit event (/etc/security/audit_event)
# Depends on the Mac OS X version.
BSM_AUDIT_EVENT = {}

##### STRUCTURES #####

# BSM Structures, I have ommited the ID always. I use the BSM_TYPE first and then, the structure.

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
    construct.UBInt8('status'),
    construct.UBInt32('return_value'))

BSM_TOKEN_TRAILER = construct.Struct(
    'bsm_token_trailer',
     construct.UBInt16('magic'),
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

# TODO: This structure has some issues and unknown fields.
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

##### TOKEN ID ####

# List of valid Token_ID
# Token_ID -> [NAME_STRUCTURE, STRUCTURE]
'''
    Mac OS X Token ID validated:
    BSM_TOKEN_TRAILER == 19 (0x13)
    BSM_HEADER == 20 (0x14)
    BSM_TOKEN_PATH  == 35 (0x23)
    BSM_TOKEN_SUBJECT == 36 (0x24)
    BSM_TOKEN_EXIT == 39 (0x27)
    BSM_TOKEN_TEXT == 40 (0x28)
    BSM_TOKEN_ARGUMENT_32 == 45 (0x2d)
    BSM_TOKEN_ARGUMENT_64 == 113 (0x71)
    BSM_TOKEN_SUBJECT_EX == 122 (0x7a)
    
    Read in OpenBSM: "audit_record.h", unvalidated:
    #define	AUT_INVALID		0x00
    #define	AUT_OTHER_FILE32	0x11
    #define	AUT_OHEADER		0x12
    #define	AUT_HEADER32_EX		0x15
    #define	AUT_DATA		0x21
    #define	AUT_IPC			0x22
    #define	AUT_XATPATH		0x25
    #define	AUT_PROCESS32		0x26
    #define	AUT_OPAQUE		0x29
    #define	AUT_IN_ADDR		0x2a
    #define	AUT_IP			0x2b
    #define	AUT_IPORT		0x2c
    #define	AUT_SOCKET		0x2e
    #define	AUT_SEQ			0x2f
    #define	AUT_ACL			0x30
    #define	AUT_ATTR		0x31
    #define	AUT_IPC_PERM		0x32
    #define	AUT_LABEL		0x33
    #define	AUT_GROUPS		0x34
    #define	AUT_ACE			0x35
    #define	AUT_PRIV		0x38
    #define	AUT_UPRIV		0x39
    #define	AUT_LIAISON		0x3a
    #define	AUT_NEWGROUPS		0x3b
    #define	AUT_EXEC_ARGS		0x3c
    #define	AUT_EXEC_ENV		0x3d
    #define	AUT_ATTR32		0x3e
    #define	AUT_UNAUTH		0x3f
    #define	AUT_XATOM		0x40
    #define	AUT_XOBJ		0x41
    #define	AUT_XPROTO		0x42
    #define	AUT_XSELECT		0x43
    #define	AUT_XCOLORMAP		0x44
    #define	AUT_XCURSOR		0x45
    #define	AUT_XFONT		0x46
    #define	AUT_XGC			0x47
    #define	AUT_XPIXMAP		0x48
    #define	AUT_XPROPERTY		0x49
    #define	AUT_XWINDOW		0x4a
    #define	AUT_XCLIENT		0x4b
    #define	AUT_CMD			0x51
    #define	AUT_EXIT		0x52
    #define	AUT_ZONENAME		0x60
    #define	AUT_HOST		0x70
    #define	AUT_RETURN64		0x72
    #define	AUT_ATTR64		0x73
    #define	AUT_HEADER64		0x74
    #define	AUT_SUBJECT64		0x75
    #define	AUT_PROCESS64		0x77
    #define	AUT_OTHER_FILE64	0x78
    #define	AUT_HEADER64_EX		0x79
    #define	AUT_PROCESS32_EX	0x7b
    #define	AUT_SUBJECT64_EX	0x7c
    #define	AUT_PROCESS64_EX	0x7d
    #define	AUT_IN_ADDR_EX		0x7e
    #define	AUT_SOCKET_EX		0x7f
'''
# Only the checked structures are been added to the valid structures lists.
BSM_TYPE_LIST = {
19 : ['BSM_TOKEN_TRAILER', BSM_TOKEN_TRAILER],
20 : ['BSM_HEADER', BSM_HEADER],
35 : ['BSM_TOKEN_PATH', BSM_TOKEN_PATH],
36 : ['BSM_TOKEN_SUBJECT', BSM_TOKEN_SUBJECT],
39 : ['BSM_TOKEN_EXIT', BSM_TOKEN_EXIT],
40 : ['BSM_TOKEN_TEXT', BSM_TOKEN_TEXT],
45 : ['BSM_TOKEN_ARGUMENT_32', BSM_TOKEN_ARGUMENT_32],
113 : ['BSM_TOKEN_ARGUMENT_64', BSM_TOKEN_ARGUMENT_64],
122 : ['BSM_TOKEN_SUBJECT_EX', BSM_TOKEN_SUBJECT_EX]}


#### FUNCTIONS ####

# Create the audit-event text representation
def CreateStructureAuditEvent():
  try:
    f = open(BSM_AUDIT_EVENT_FILE, 'rb')
  except:
    print ('[WARNING] The Audit Event File {} not found, '
           'the text type can not be represented'.format(BSM_AUDIT_EVENT_FILE))
    return
  line = f.readline()
  while line:
    # Not a comment
    if not line.startswith('#'):
      split_line = line.split(':')
      try:
        # Add the type
        BSM_AUDIT_EVENT.update({int(split_line[0]) : split_line[2]})
      except:
        print 'Unknown entry in {0}: "{1}"'.format(BSM_AUDIT_EVENT_FILE, line)
    line = f.readline()
  
# Formating a Token to be printed.
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
    elem.append('\t* Event Type: {0} ({1})'.format(
        BSM_AUDIT_EVENT.get(token.event_type, 'UNKNOWN'), token.event_type))
    elem.append('\t* Modifier: {}'.format(token.modifier))
    elem.append('\t* Time: {2} ({0}.{1})'.format(token.timestamp, token.microsecond, time.strftime(
        '%Y-%m-%d %H:%M:%S', time.gmtime(token.timestamp))))
  elif id == 'BSM_TOKEN_EXIT':
    elem.append('\t* Exit {0}({1}), Return value {2}'.format(
        BSM_ERRORS.get(token.status, 'UNKNOWN'), token.status, token.return_value))
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
          if (data.magic != int(BSM_TOKEN_TRAILER_MAGIC, 16)):
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
  if header.version != AUDIT_HEADER_VERSION:
    print '[WARNING] BSM version {} not supported.'.format(header.version)
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

  try:
    f = open(log, 'rb')
  except:
    print '[Error] The file BSM does not exist'
    exit(1)
  CreateStructureAuditEvent()
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

