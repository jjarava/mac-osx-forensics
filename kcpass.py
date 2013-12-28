#!/usr/bin/python

import sys

magic='7d895223d2bcddeaa3b91f'
pwd = ''

if len(sys.argv) != 2:
  print 'Please write as a first argv the hexadecimal kcpassword value:'
  print 'Example: python {} 1ceb3147d2172f1140ff63bf'.format(sys.argv[0])
  exit(1)

kcpasswd=sys.argv[1]
print u'\n\tKcpasswd: 0x{}.'.format(kcpasswd)
print u'\tMagic Xor: 0x{}.'.format(magic)

i = 0
while i < len(kcpasswd):
  charkc = kcpasswd[i] + kcpasswd[i+1]
  charkch = int(charkc, 16)
  charm = magic[i] + magic[i+1]
  charmh = int(charm, 16)
  r = charkch ^ charmh
  pwd += chr(r)
  if r == 0:
    print '\tThe password is: "{}".\n'.format(pwd)
    break
  i += 2
