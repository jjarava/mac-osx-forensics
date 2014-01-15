#!/usr/python
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
"""Mac OS X Artifacts."""

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

import sys
import plistlib
from binplist import binplist

name = sys.argv[1]
fd = open(name, 'rb')
plist = binplist.BinaryPlist(fd, False, False)

print u'File: {}'.format(name)

try:
  parsed_plist = plist.Parse()
except binplist.FormatError, e:
  try:
    parsed_plist = plistlib.readPlist(name)
  except:
    print "Not a valid plist file."
    exit(1)

# Time Machine // com.apple.TimeMachine.plist
try:
  destinations = parsed_plist['Destinations']
except KeyError:
  destinations = None
if destinations:
  for destination in destinations:
    uuid = destination['DestinationUUIDs']
    if not uuid:
      uuid = 'Unknown device'
    print u'TimeMachine Device: {}'.format(uuid)
    for date in destination['SnapshotDates']:
      print u'Backup at {}'.format(date)

# Bluetooth Device // com.apple.Bluetooth.plist
try:
  devices = parsed_plist['DeviceCache']
except KeyError:
  devices = None
if devices:
  for mac_device in devices:
    device = devices[mac_device]
    try:
      name = device['Name']
    except KeyError:
      name = 'Unknown'
    timestamp = device['LastInquiryUpdate']
    print u'Last bluetooth {}({}) connected at {}'.format(
        name, mac_device, timestamp)

# Airport Wifi stored // com.apple.airport.preferences.plist
try:
  wifis = parsed_plist['RememberedNetworks']
except KeyError:
  wifis = None
if wifis:
  for wifi in wifis:
    timestamp = wifi['LastConnected']
    ssid = wifi['SSIDString']
    security = wifi['SecurityType']
    print u'Last connection at {} in Wifi "{}" with security "{}"'.format(
        timestamp, ssid, security)

# Mac OS X Updates // com.apple.SoftwareUpdate.plist
try:
  updatefull = parsed_plist['LastFullSuccessfulDate']
  print u'Full Mac OS X update at {}'.format(updatefull)
except KeyError:
  pass
try:
  update = parsed_plist['LastSuccessfulDate']
  print u'Partial Mac OS X update at {}'.format(update)
except KeyError:
  pass

# /Users/user/Library/Preferences/
# Associate extension application // com.apple.spotlight.plist
try:
  extensions = parsed_plist['UserShortcuts']
except KeyError:
  extensions = None
if extensions:
  for name_extension in extensions:
    extension = extensions[name_extension]
    path = extension['PATH']
    name = extension['DISPLAY_NAME']
    last_used = extension['LAST_USED']
    print u'Extension {} opened by {} ({}) was openned last time at {}'.format(
         name_extension, name, path, last_used)

# /Users/user/Library/Preferences/ByHost/
# Apple Accounts // com.apple.coreservices.appleidauthenticationinfo.*.plist
try:
  accounts = parsed_plist['Accounts']
  _ = parsed_plist['AuthCertificates']
  _ = parsed_plist['AccessorVersions']
except KeyError:
  accounts = None
if accounts:
  for name_account in accounts:
    account = accounts[name_account]
    try:
      apple_id = account['AppleID']
    except KeyError:
      break
    name = account['FirstName']
    family_name = account['LastName']
    uuid = ['AccountUUID']
    creationTime = account['CreationDate']
    lastTime = account['LastSuccessfulConnect']
    validateTime = account['ValidationDate']
    
    print u'Apple account {} ({} {}) created at {}'.format(
        name_account, name, family_name, creationTime)
    print u'Apple account {} ({} {}) last time used at {}'.format(
        name_account, name, family_name, lastTime)
    print u'Apple account {} ({} {}) last validated at {}'.format(
        name_account, name, family_name, validateTime)

################ NO TIMESTIME ####################
# /Users/moxilo/Library/Preferences
# Recent documents
#     com.apple.Console.LSSharedFileList.plist
#     com.apple.Preview.LSSharedFileList.plist
#     com.apple.TextEdit.LSSharedFileList.plist
#     com.apple.recentitems.plist
try:
  documents = parsed_plist['RecentDocuments']
except KeyError:
  documents = None
if documents:
  for doc in documents['CustomListItems']:
    name = name.split('/').pop().replace('.plist', '').replace('.LSSharedFileList', '')
    print u'Recent document in {}: {}'.format(
        name, doc['Name'])
    # TODO: Specific Binary Structure, it must be parsed.
    #print doc['Bookmark']

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
    #print doc['Bookmark']

