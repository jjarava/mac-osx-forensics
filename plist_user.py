#!/usr/bin/python
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
""" Mac OS X 10.8 and 10.9 User Accounts """

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

from binplist import binplist
import xml.etree.ElementTree
import sys
import os
import binascii

# Author: Kiddi G. 
class FooFile(object):
  def __init__(self, data):
    self._data = data
    self._offset = 0

  def tell(self):
    return self._offset

  def seek(self, offset, whence=os.SEEK_SET):
    if whence == os.SEEK_SET:
      self._offset = offset
    elif whence == os.SEEK_CUR:
      self._offset += offset
    elif whence == os.SEEK_END:
      self._offset = len(self._data) + offset

  def read(self, size=0):
    if self._offset > len(self._data):
      return ''

    if not size:
      data_to_return = self._data[self._offset:]
      self._offset = len(self._data)
      return data_to_return

    if size >= len(self._data[self._offset:]):
      data_to_return = self._data[self._offset:]
      self._offset = len(self._data)
      return data_to_return

    data_to_return = self._data[self._offset:self._offset + size]
    self._offset += size
    return data_to_return

  def close(self):
    pass


name = sys.argv[1]

fd = open(name, 'rb')
plist = binplist.BinaryPlist(fd, False, False)
parsed_plist = plist.Parse()
account = parsed_plist['name'][0]
name = parsed_plist['realname'][0]
uid = parsed_plist['uid'][0]
gid = parsed_plist['gid'][0]
shell = parsed_plist['shell'][0]
password = parsed_plist['authentication_authority']
ShadowHashData = parsed_plist['ShadowHashData']
foo = FooFile(ShadowHashData[0])
plist_file = binplist.BinaryPlist(file_obj=foo)
top_level = plist_file.Parse()['SALTED-SHA512-PBKDF2']
salt = binascii.hexlify(top_level['salt'])
entropy = binascii.hexlify(top_level['entropy'])
iterations = top_level['iterations']

policy = parsed_plist['passwordpolicyoptions'][0]
# TODO: beautiful hack because bplist return a string instead of dict
list_timestamp = []
key = ''
# XML extraction.
xml_policy = xml.etree.ElementTree.fromstring(policy)
for dic in xml_policy.iterfind('dict'):
  for elem in dic:
    if elem.tag == u'key':
      key = elem.text
    elif elem.tag == u'date':
      list_timestamp.append([key, elem.text])

print u'\nUser: {}'.format(account)
print u'UID: {}'.format(uid)
print u'GID: {}'.format(gid)
print u'Shell: {}'.format(shell)
print u'Policy:'.format()
for time_elem in list_timestamp:
    print u'  {} at {}.'.format(time_elem[0], time_elem[1])
print u'Available Passwords:'.format()
for password in parsed_plist['authentication_authority']:
  if password.startswith(';ShadowHash'):
    print u' Mac OS X user password:'
    print u'  Iterations: {}'.format(iterations)
    print u'  Salt: {}'.format(salt)
    print u'  Entropy: {}'.format(entropy)
  elif password.startswith(';Kerberos'):
    listKerberos = password.split(';')
    print u' Kerberos:'
    print u'  Version: {}'.format(listKerberos[1])
    print u'  Hash: {}'.format(listKerberos[4])
  else:
    print u' {}'.format(password)
print u''.format()
print u''.format()

# from pbkdf2 import crypt
# password = 'abcd'
# result = crypt(password, salt, iterations).split('$')

fd.close()
