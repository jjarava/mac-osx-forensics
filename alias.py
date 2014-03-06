#!/usr/bin/python

import binascii
import construct
import datetime
import sys

from binplist import binplist

HFS_to_Epoch = 2082844800
s_alias = construct.Struct(
    'plist_alias',
    construct.Padding(4),
    construct.UBInt16('length'),
    construct.Padding(6),
    construct.UBInt32('timestamp1'),
    construct.Padding(18),
    construct.UBInt32('timestamp2'),
    construct.Padding(20))

s_type = construct.UBInt16('type')

s_volume = construct.Struct(
    'volume',
    construct.UBInt16('volume1_length'),
    construct.UBInt16('characters1'),
    construct.String(
        'volume1',
        lambda ctx: ctx.characters1 * 2),
    construct.Padding(2),
    construct.UBInt16('volume2_length'),
    construct.UBInt16('characters2'),
    construct.String(
        'volume2',
        lambda ctx: ctx.characters2 * 2))

s_mount_point = construct.PascalString(
        'mount_point',
        length_field = construct.UBInt16('length'))

def __init__():
  f = open (sys.argv[1], 'rb')
  plist = binplist.BinaryPlist(f, False, False)
  try:
    parsed_plist = plist.Parse()
  except binplist.FormatError:
    print "Error!"
    exit()
  '''
  system_items = parsed_plist['systemitems']
  elem_list = system_items['VolumesList']
  favorite_items = parsed_plist['favorites']
  elem_list.extend(favorite_items['VolumesList'])
  '''
  favorite_items = parsed_plist['favorites']
  elem_list = favorite_items['VolumesList']
  for volume in elem_list:
    if 'Alias' in volume:
      try:
        data = volume['Alias']
        s = s_alias.parse(data)
        data = data[s_alias.sizeof():]

        # Search for 0x000e volume ID
        type = s_type.parse(data)
        data = data[s_type.sizeof():]
        while type != 14 and data != '':
          type = s_type.parse(data)
          data = data[s_type.sizeof():]
      except:
        print "Fail!"
        continue

      # If not volume ID
      if data == '':
        print "Fail!"
        continue
      v = s_volume.parse(data)
      time = datetime.datetime.fromtimestamp(
          s.timestamp1 - HFS_to_Epoch).strftime('%Y-%m-%d %H:%M:%S')
      print u'\n\tFile name: {}'.format(v.volume1)
      print u'\tVolume name: {}'.format(v.volume2)
      print u'\tTime: {}'.format(time)
      if s.timestamp1 != s.timestamp2:
        time = datetime.datetime.fromtimestamp(
            s.timestamp2 - HFS_to_Epoch).strftime('%Y-%m-%d %H:%M:%S')
        print u'\tSecond time: {}'.format(time)
      
      type = s_type.parse(data)
      data = data[s_type.sizeof():]
      while type != 19 and data != '':
        type = s_type.parse(data)
        data = data[s_type.sizeof():]
      if data == '':
        continue
      mount_point = s_mount_point.parse(data)
      print u'\tMount point: {}'.format(mount_point)
__init__()
