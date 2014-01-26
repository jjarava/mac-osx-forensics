#!/usr/bin/python
# -*- coding: utf-8 -*-

import construct
import plistlib
import sys
import time
from binplist import binplist

HEADER = construct.Struct(
  'header',
  construct.String('magic', 4),
  construct.ULInt32('length'),
  construct.ULInt32('unknown1'),
  construct.Padding(36),
  construct.ULInt32('unknown2'))
TOKEN = construct.Struct(
  'token',
  construct.ULInt32('length'),
  construct.ULInt32('type'))
STR = construct.String('string', 4)
INT = construct.ULInt32('integer')
INT64 = construct.ULInt64('integer')

def ParseBookmark(bookmark):
  header = HEADER.parse(bookmark)
  if 'book' != header.magic:
    return

  bookmark = bookmark[HEADER.sizeof():]
  
  token = TOKEN.parse(bookmark)
  bookmark = bookmark[TOKEN.sizeof():]  
  
  # PATH
  path = ''
  elem = 0
  while(token.type == 257):
    bookmark, value = getData(bookmark, token.length, token.type)
    path += '/' + value
    elem += 1
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
  print u'\tPath: {}'.format(path)

  # INODE PATH
  # Element 1537
  if token.type == 1537:
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    # 772 elements
    inodes = []
    while(token.type == 772): 
      bookmark, value = getData(bookmark, token.length, token.type)
      inodes.append(value)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
    if inodes:
      print u'\tInode Path: /{}'.format(u'/'.join(inodes))
      if len(inodes) != elem:
        print "\tWarning: the original path and the new path are different, check Sandbox Path."
    # Element 1537
    bookmark, value = getData(bookmark, token.length, token.type) 
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    
  # Timestamp
  bookmark, value = getData(bookmark, token.length, token.type)
  token = TOKEN.parse(bookmark)
  bookmark = bookmark[TOKEN.sizeof():]
  # 513
  bookmark, value = getData(bookmark, token.length, token.type)
  token = TOKEN.parse(bookmark)
  bookmark = bookmark[TOKEN.sizeof():]

  # User ID
  while(token.type == 771):
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    bookmark, value = getData(bookmark, token.length, token.type)
    print u'\tUser ID: {}'.format(value)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]

  # If external device
  while(token.type == 772):
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    if token.type == 771:
      bookmark, value = getData(bookmark, token.length, token.type)
      print u'\tUser ID: {}'.format(value[1:-1])
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
    elif(token.type == 1024):
      bookmark, value = getData(bookmark, token.length, token.type)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
      # 513
      bookmark, value = getData(bookmark, token.length, token.type)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
      # External montpoint
      if token.type == 257:
        bookmark, value = getData(bookmark, token.length, token.type)
        print u'\tExternal device: {}'.format(value)
        token = TOKEN.parse(bookmark)
        bookmark = bookmark[TOKEN.sizeof():]

  # Hardisk Partition
  if token.type == 257:
    bookmark, value = getData(bookmark, token.length, token.type)
    print u'\tHD Partition Root Name: {}'.format(value)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():] 
      
  # UUID
  if token.type == 772:
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    # 1024
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    if token.type == 257:
      bookmark, value = getData(bookmark, token.length, token.type)
      print u'\tHD Root UUID: {}'.format(value)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
       
  # 513
  if token.type == 513:
    bookmark, value = getData(bookmark, token.length, token.type)
    # print u'\tUnknown {}: {}'.format(token.type, value)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    # Mount disk
    if token.type == 257:
      bookmark, value = getData(bookmark, token.length, token.type)
      print u'\tHD Root mount in: {}'.format(value)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]
  
  # 1281
  if token.type == 1281:
    bookmark, value = getData(bookmark, token.length, token.type)
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]  
    # 513
    if token.type == 513:
      bookmark, value = getData(bookmark, token.length, 257)
      elements = value.split(';')
      sandbox_name = elements[0]
      sandbox_path = elements[len(elements)-1]
      print u'\tSandbox ID: {}'.format(sandbox_name)
      print u'\tSandbox Path: {}'.format(sandbox_path)
      token = TOKEN.parse(bookmark)
      bookmark = bookmark[TOKEN.sizeof():]

    
def getData(data, length, type):
  times = length // 4
  if length % 4 > 0:
    times += 1
  # Text
  if type == 257:
    value = ''
    for i in range(times):
      value += u'{}'.format(STR.parse(data))
      data = data[4:]
    value, _, _ = value.partition('\x00')
    return (data, u'{}'.format(value))
  # Timestamp
  elif type == 1024:
    t = INT.parse(data)
    t64 = INT64.parse(data)
    data = data[8:]    
    return (data, '{}, {}'.format(t, t64))
  else:
    value = []
    for i in range(times):
      value.append(INT.parse(data))
      data = data[4:]
    # Inode
    if type == 772:
      return (data, u'{}'.format(value[0]))
    return (data, u'{}'.format(value))

def DebugParseBookmark(bookmark):
  print "-----------"
  header = HEADER.parse(bookmark)
  if 'book' != header.magic:
    return
  bookmark = bookmark[HEADER.sizeof():]
  while (len(bookmark) > 0):
    token = TOKEN.parse(bookmark)
    bookmark = bookmark[TOKEN.sizeof():]
    times = token.length // 4
    if token.length % 4 > 0:
      times += 1
    if token.type == 257: # or token.type == 513:
      value = ''
      for i in range(times):
        value += u'{}'.format(STR.parse(bookmark))
        bookmark = bookmark[4:]
      print u'Text: {}'.format(value)
    else:
      value = []
      for i in range(times):
        value.append(INT.parse(bookmark))
        bookmark = bookmark[4:]
      if token.type == 1024:
        t = value.pop(0) + 978307200
        timestamp = time.strftime(
            '%Y-%m-%d %H:%M:%S', time.localtime(t))
        print u'Timestamp: {}, extra: {}'.format(
            timestamp, value)
      else:
        print u'Unknown type {}({}): {}'.format(
            token.type, hex(token.type), value)
  print "--------///-------"

name = sys.argv[1]
fd = open(name, 'rb')
plist = binplist.BinaryPlist(fd, False, False)

print u'File: {}\n'.format(name)

try:
  parsed_plist = plist.Parse()
except binplist.FormatError, e:
  parsed_plist = plistlib.readPlist(name)


# /Users/moxilo/Library/Preferences
# Recent documents
#     com.apple.PROGRAM.LSSharedFileList.plist
#     com.apple.recentitems.plist
try:
  documents = parsed_plist['RecentDocuments']
except KeyError:
  documents = None
if documents:
  for doc in documents['CustomListItems']:
    name = name.split('/').pop().replace('.plist', '').replace('.LSSharedFileList', '')
    info_program = name.split('.')
    company = info_program[1]
    program = info_program[2]
    print u'\tRecent document open by {}({}): {}'.format(
        program, company, doc['Name'])
    # TODO: Specific Binary Structure, it must be parsed.
    ParseBookmark(doc['Bookmark'])
    print ''

try:
  documents = parsed_plist['RecentApplications']
except KeyError:
  documents = None
if documents:
  for doc in documents['CustomListItems']:
    name = name.split('/').pop()
    print u'Recent applications in {}: {}'.format(
        name, doc['Name'])
    # TODO: Specific Binary Structure, it must be parsed.
    ParseBookmark(doc['Bookmark'])

