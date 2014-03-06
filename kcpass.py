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
""" KCPassword Xor """

# MSc Project in Royal Holloway, University of London.
__author__ = 'Joaquin Moreno Garijo (bastionado@gmail.com)'

import sys

magic_static='7d895223d2bcddeaa3b91f'
pwd = ''

if len(sys.argv) != 2:
  print 'Please write as a first argv the hexadecimal kcpassword value:'
  print 'Example: python {} 1ceb3147d2172f1140ff63bf'.format(sys.argv[0])
  exit(1)

kcpasswd=sys.argv[1]
print u'\n\tKcpasswd: 0x{}.'.format(kcpasswd)
print u'\tMagic Xor: 0x{}.'.format(magic_static)

tam_xor = len(magic_static)
tam = len(kcpasswd) - tam_xor
magic = magic_static
while tam > 0:
  tam -= tam_xor
  magic += magic_static
print u'\tUsed Magic Xor: 0x{}.'.format(magic)

i = 0
while i < len(kcpasswd):
  charkc = kcpasswd[i] + kcpasswd[i+1]
  charkch = int(charkc, 16)
  charm = magic[i] + magic[i+1]
  charmh = int(charm, 16)
  r = charkch ^ charmh
  pwd += chr(r)
  if r == 0:
    print '\n\tThe password is: "{}".\n'.format(pwd)
    break
  i += 2
