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
""" UTMPX file parsed """

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

# README:
# The goal of this tools is only for developing purpose.
# The full documented and well implemented version is going to be in PLASO:
# https://code.google.com/p/plaso/
# http://plaso.kiddaland.net/


# Disclaimer: it only was probed in 10.9.

import construct
import os
import re
import sys
import time

# Magic header
MAGIC = 'utmpx-1.00'
MAGIC_HEX = '75746d70782d312e3030'

# [HEADER] [STRUCT]*

# Header of the UTMPX file
MAC_UTMPX_HEADER = construct.Struct(
    'header',
    construct.Bytes('magic', 10),
    construct.Padding(286),
    construct.ULInt16('id'),
    construct.Padding(622),
    construct.ULInt32('unknown1'),
    construct.ULInt32('unknown2'),
    construct.ULInt32('timestamp'),
    construct.Padding(324))

# Struct from one entry
MAC_UTMPX_STRUCT = construct.Struct(
    'utmpx_mac',
    construct.String('user', 256),
    construct.ULInt32('id'),
    construct.String('tty_name', 32),
    construct.ULInt32('pid'),
    construct.ULInt32('status_type'),
    construct.ULInt32('timestamp'),
    construct.ULInt32('microsecond'),
    construct.String('hostname', 256),
    construct.Padding(64))

# Status of the session
MAC_STATUS_TYPE = {
    0 : 'EMPTY',
    1 : 'RUN_LVL',
    2 : 'BOOT_TIME',
    3 : 'OLD_TIME',
    4 : 'NEW_TIME',
    5 : 'INIT_PROCESS',
    6 : 'LOGIN_PROCESS',
    7 : 'USER_PROCESS',
    8 : 'DEAD_PROCESS'}

# By default where the file is.
DIRNAME = '/private/var/run'
FILENAME = 'utmpx'

# Printing the file Header values.
#
# Args:
#  header: the struct header of the file.
#  path: the path of the file.
def printHeader(header, path):
  txt_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000",
                           time.gmtime(header.timestamp))
  print '\n   UTMPX File: [{}]\n'.format(path)
  print '   Header:'
  print '\tID: {}'.format(header.id)
  print '\tUptimeTime: {} ({})\n'.format(
      txt_time, header.timestamp)

# Print an entry (Session).
#
# Args:
#  entry: number of the entry.
#  user: user of the session.
#  terminal: name of the terminal.
#  hostname: the name of the host (source)
#  name_status: the text representation of the status.
#  num_status: the numerical representation of the status.
#  timestamp: the epoch timestamp.
def printEntry(entry, user, terminal, hostname, name_status, num_status, timestamp):
  print '\tEntry: {}'.format(entry)
  print '\t* User: {}'.format(user)
  print '\t* Terminal: {}'.format(terminal)
  print '\t* Hostname: {}'.format(hostname)
  print '\t* Status: {0} ({1:#04x})'.format(name_status, num_status)
  print '\t* Timestamp: {} ({})'.format(
      time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(timestamp)),
      timestamp)
  print '\t------------------------------'

# Read an entry.
#
# Args:
#   f: the utmpx file name.
#   entry_number: the number of the entry it reads.
def ReadEntry(f, entry_number):
    data = f.read(MAC_UTMPX_STRUCT.sizeof())
    # End of file
    if len(data) != MAC_UTMPX_STRUCT.sizeof():
        return False
    try:
        entry = MAC_UTMPX_STRUCT.parse(data)
    except:
        print 'Unable to parse Mac OS X UTMPX event.'
        return True
    user, _, _ = entry.user.partition('\x00')
    if not user:
        user = 'N/A'
    terminal, _, _ = entry.tty_name.partition('\x00')
    if not terminal:
        terminal = 'N/A'
    hostname, _, _ = entry.hostname.partition('\x00')
    if not hostname:
      hostname = 'localhost'
    name_status = MAC_STATUS_TYPE.get(entry.status_type, 'N/A')
    printEntry(entry_number, user, terminal, hostname, name_status, entry.status_type, entry.timestamp)
    return True

# Main
def __init__():
  try:
    if len(sys.argv) == 1:
      path = os.path.join(DIRNAME, FILENAME)
    elif len(sys.argv) == 2:
      path = sys.argv[1]
    else:
      path = ''
    f = open(path, 'rb')
  except IOError:
    print u'File {} not found'.format(path)
    exit(1)
  except:
    print u'Usage: python {} [file]'.format(sys.argv[0])
    exit(1)

  try:
    header = MAC_UTMPX_HEADER.parse_stream(f)
  except:
    print 'Not a Mac UTMPX Header, unable to parse.'
    exit(1)

  if header.magic != MAGIC:
    print 'Not a valid Mac Os X UTMPX Header.'
    exit(1)

  printHeader(header, path)

  entry_number = 1
  result = ReadEntry(f, entry_number)
  while result:
    entry_number += 1
    result = ReadEntry(f, entry_number)


  f.close()

__init__()
