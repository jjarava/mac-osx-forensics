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
"""Cups Reading Control Files."""

# IMPORTANT: DIRTY PARSE...

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

import datetime
import construct
import sys

header = construct.Padding(11)
attr_id = construct.UBInt8('type')
attr_text = construct.CString('text')
attr_time = construct.Struct(
    'time',
    construct.UBInt32('timestamp'),
    construct.UBInt16('other'))

class ControlFile(object):

  def __init__(self):
    self.crt_time = 0
    self.proc_time = 0
    self.comp_time = 0
    self.data = []

def printValue(name, value):
  # print u'{}: {}'.format(name, value)
  if type(name) != str and type(name) != unicode:
    return
  elif name == u'printer-uri':
    document.data.append(u'URI: {}'.format(value))
  elif name == u'job-uuid':
    document.data.append(u'Job ID: {}'.format(value))
  elif name == u'copies':
    document.data.append(u'Copies: {}'.format(value))
  elif name == u'DestinationPrinterID':
    document.data.append(u'Printer ID: {}'.format(value))
  elif name == u'job-originating-user-name':
    document.data.append(u'User: {}'.format(value[:-1]))
  elif name == u'job-name':
    document.data.append(u'Job name: {}'.format(value[:-1]))
  elif name == u'document-format':
    document.data.append(u'Document format: {}'.format(value[:-1]))
  elif name == u'job-originating-host-name':
    document.data.append(u'Computer name: {}'.format(value[:-1]))
  elif name == u'com.apple.print.JobInfo.PMApplicationName':
    document.data.append(u'Application: {}'.format(value[:-1]))
  elif name == u'com.apple.print.JobInfo.PMJobOwner':
    document.data.append(u'Owner: {}'.format(value[:-1]))
  elif name.startswith('com.apple.print.PrintSettings'):
    if name == u'com.apple.print.PrintSettings.PMCopies':
      document.data.append(u'Copies: {}'.format(value[:-1]))
  elif name == u'time-at-creation':
    document.crt_time = u'{}'.format(value)
  elif name == u'time-at-processing':
    document.proc_time = u'{}'.format(value)
  elif name == u'time-at-completed':
    document.comp_time = u'{}'.format(value)

def compare(text1, text2):
  i = 0
  while(i < len(text1) and i < len(text2)):
    if text1[i] != text2[i]:
      print u'Difference in {}: "{}" "{}"'.format(i, text1[i], text2[i])
      break
    i += 1

def getTime(epoch):
  return datetime.datetime.fromtimestamp(
      float(epoch)).strftime('%Y-%m-%d %H:%M:%S')

def Pair(f):
  name = Parse(f)
  if name == None:
    return False
  value = Parse(f)
  if value == '':
    value = Parse(f)
  if value == None:
    return False
  printValue(name, value)
  return True

def Parse(f):
  try:
    id = attr_id.parse_stream(f)
    if id == 4:
      time = attr_time.parse_stream(f)
      return time.timestamp
    else:
      text = attr_text.parse_stream(f)
    return u'{}'.format(text)
  except:
    return None

f = open(sys.argv[1],'rb')
header.parse_stream(f)


document = ControlFile()
more = Pair(f)
while(more):
  more = Pair(f)

if document.crt_time:
  print u'Creation time: {} ({}).'.format(
      getTime(document.crt_time), document.crt_time)
if document.proc_time:
  print u'Process time: {} ({}).'.format(
      getTime(document.proc_time), document.proc_time)
if document.comp_time:
  print u'Completed time: {} ({}).'.format(
      getTime(document.comp_time), document.comp_time)
print u'\n'.join(document.data)
print u'------------------------'

f.close()

