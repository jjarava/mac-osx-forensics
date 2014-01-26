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
""" The wifi.log parser. """

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (Joaquin.MorenoGarijo.2013@live.rhul.ac.uk)'

# README:
# # The goal of this tools is only for developing pourpose.
# The full documented and well implemented version is going to be in PLASO:
# https://code.google.com/p/plaso/
# http://plaso.kiddaland.net/


# Disclaimer: it only was probed in 10.9.

import os
import re
import sys
import time

# Print all records (True/False)
ALL = False

# Default place of the file
DIRNAME = '/private/var/log'
FILENAME = 'wifi.log'

def getEpochTime(timestamp):
  pattern = '%d %b %Y %H:%M:%S'
  aux = time.strptime(timestamp, pattern)
  return int(time.mktime(aux))

def getAction(agent, action, msg):
  if 'airportd' in agent:
    if 'airportdProcessDLILEvent' in action:
      interface = msg.split()[0]
      return 'Interface {} turn up.'.format(interface)
    elif 'doAutoJoin' in action:
      ssid = 'Unknown'
      exp_reg = re.match(r'Already\sassociated\sto\s(.*)\.\sBailing', msg)
      if exp_reg:
        ssid = exp_reg.group(1)
      return 'Wifi connected to SSID {}'.format(ssid)
    elif 'processSystemPSKAssoc' in action:
      ssid = 'Unknown'
      for i in re.findall(r'(?<=\[ssid=).*?(?=, bssid=)', msg):
        ssid = i
      bssid = 'Unknown'
      for i in re.findall(r'(?<=bssid=).*?(?=, security=)', msg):
        bssid = i
      security = 'Unknown'
      for i in re.findall(r'(?<=security=).*?(?=, rssi=)', msg):
        security = i
      aux = 'New wifi configured. BSSID: '
      return '{}{}, SSID: {}, Security: {}.'.format(
          aux, bssid, ssid, security)
  return None

def printData(timestamp, epoch, agent, action, message):
  print '[{}] ({}) Agent: {} Action: {} [{}]'.format(timestamp, epoch, agent, action, message)

def __init__():
  #TODO: Common problem in syslog format logs. In PLASO version is much more better :-).
  year = time.strftime("%Y", time.gmtime())
  print '\n\n\t[IMPORTANT] The year {} is selected as a year of the timestamp!!!!\n\n'.format(year)
  
  if len(sys.argv) > 2:
      print 'Use: python {0} wififile'.format(sys.argv[0])
      exit(1)

  try:
      if len(sys.argv) == 1:
        path = os.path.join(DIRNAME, FILENAME)
      elif len(sys.argv) == 2:
        path = sys.argv[1]
      f = open(path, 'r')
  except:
      print u'[Error] File [{}] not found.'.format(path)
      exit(1)

  Day_Name = r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s?'
  Moth_Name = r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
  Day_Number = r'(\d{1,2})\s+'
  Time = r'([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]{3}\s+'
  Agent = r'\<([^\>]+)\>\s+'
  Function = r'([^:]+):\s+'
  Message = r'([^\n]+)'
  Expression = Day_Name + Moth_Name + Day_Number + Time + Agent + Function + Message
    
  for line in f:
    resul = re.match(Expression, line)

    if resul:
      dn = resul.group(1)
      mn = resul.group(2)
      dn = resul.group(3)
      t = resul.group(4)
      ag = resul.group(5)
      act = resul.group(6)
      msg = resul.group(7)
      
      timestamp = u'{} {} {} {}'.format(dn, mn, year, t)
      #print '[{}]  {} @ {}  @ {}'.format(timestamp, ag, act, msg)

      action = getAction(ag, act, msg)
      if action:
        epoch = getEpochTime(timestamp)
        printData(timestamp, epoch, ag, action, msg)
      elif ALL:
        printData(timestamp, epoch, ag, 'Unknown', msg)

  f.close()

__init__()
