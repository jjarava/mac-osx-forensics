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
# The goal of this tools is only for developing purposes.
# The full documented and well implemented version is going to be in PLASO:
# https://code.google.com/p/plaso/
# http://plaso.kiddaland.net/

# Disclaimer: it only was probed in 10.8, 10.9 and OpenBSM.

# TODO: Not all the structures are implemented. If you find a non implemented structure, please report to
#       me the ID of the structure an a RAW example of this structure (copy 50 bytes from the address of
#       the structure. As an example, if the program tell you a [WARNING] providing an integer position
#       of the structure, you only need to calculate the size as a integer + 50 and then "xxd -l size file"

import construct
import datetime
import os
import socket
import struct
import sys
import time

##### CONSTANT #####

# BSM supported version (0x0b = 11)
AUDIT_HEADER_VERSION = 11

# Magic Trail Header
BSM_TOKEN_TRAILER_MAGIC = 'b105'

# IP Version constants.
AU_IPv4 = 4
AU_IPv6 = 16

# Arbitrary tokens.
# Type of data to print in a BSM_TOKEN_DATA.
BSM_TOKEN_DATA_TYPE = {
0: u'AUR_CHAR',
1: u'AUR_SHORT',
2: u'AUR_INT32'}

BSM_TOKEN_DATA_PRINT = {
0: u'Binary',
1: u'Octal',
2: u'Decimal',
3: u'Hexadecimal',
4: u'String'}

# Numeric ERRORS representation, read it in OpenBSM project: "audit_errno.h".
# TODO: I have been checked some of them against Mac OSX and I am changing
#       the name to be more clossed to Mac OS X and be more understandable.
BSM_ERRORS = {
    0: u'Success', 1: u'Operation not permitted',
    2: u'No such file or directory',
    3: u'No such process', 4: u'Interrupted system call',
    5: u'Input/output error', 6: u'Device not configured',
    7: u'Argument list too long', 8: u'Exec format error',
    9: u'Bad file descriptor', 10: u'No child processes',
    11: u'Resource temporarily unavailable', 12: u'Cannot allocate memory',
    13: u'Permission denied', 14: u'Bad address',
    15: u'Block device required', 16: u'Device busy', 17: u'File exists',
    18: u'ross-device link', 19: u'Operation not supported by device',
    20: u'Not a directory', 21: u'Is a directory', 22: u'Invalid argument',
    23: u'Too many open files in system',
    24: u'Too many open files', 25: u'Inappropriate ioctl for device',
    26: u'Text file busy', 27: u'File too large',
    28: u'No space left on device', 29: u'Illegal seek',
    30: u'Read-only file system', 31: u'Too many links',
    32: u'Broken pipe', 33: u'Numerical argument out of domain',
    34: u'Result too large', 35: u'No message of desired type',
    36: u'Identifier removed', 45: u'Resource deadlock avoided',
    46: u'No locks available', 47: u'Operation canceled',
    48: u'Operation not supported', 49: u'Disc quota exceeded',
    66: u'Too many levels of remote in path', 67: u'Link has been severed',
    71: u'Protocol error', 74: u'Multihop attempted',
    77: u'Bad message', 78: u'File name too long',
    79: u'Value too large to be stored in data type',
    88: u'Illegal byte sequence', 89: u'Function not implemented',
    90: u'Too many levels of symbolic links', 91: u'Restart syscall',
    93: u'Directory not empty', 94: u'Too many users',
    95: u'Socket operation on non-socket',
    96: u'Destination address required', 97: u'Message too long',
    98: u'Protocol wrong type for socket',
    99: u'Protocol not available', 120: u'Protocol not supported',
    121: u'Socket type not supported', 122: u'Operation not supported',
    123: u'Protocol family not supported',
    124: u'Address family not supported by protocol family',
    125: u'Address already in use', 126: u'Can\'t assign requested address',
    127: u'Network is down', 128: u'Network unreachable',
    129: u'Network dropped connection on reset',
    130: u'Software caused connection abort',
    131: u'Connection reset by peer', 132: u'No buffer space available',
    133: u'Socket is already connected', 134: u'Socket is not connected',
    143: u'Can\'t send after socket shutdown',
    144: u'Too many references: can\'t splice', 145: u'Operation timed out',
    146: u'Connection refused', 147: u'Host is down',
    148: u'No route to host', 149: u'Operation already in progress',
    150: u'Operation now in progress', 151: u'Stale NFS file handle',
    190: u'PROCLIM', 191: u'BADRPC', 192: u'RPCMISMATCH',
    193: u'PROGUNAVAIL', 194: u'PROGMISMATCH', 195: u'PROCUNAVAIL',
    196: u'FTYPE', 197: u'AUTH', 198: u'NEEDAUTH', 199: u'NOATTR',
    200: u'DOOFUS', 201: u'USTRETURN', 202: u'NOIOCTL', 203: u'DIRIOCTL',
    204: u'PWROFF', 205: u'DEVERR', 206: u'BADEXEC', 207: u'BADARCH',
    208: u'SHLIBVERS', 209: u'BADMACHO', 210: u'POLICY'}

# Numeric PROTOCOLS representation, read in OpenBSM project: "audit_fcntl.h".
# TODO: not checked
BSM_PROTOCOLS = {
    0: u'UNSPEC', 1: u'LOCAL', 2: u'INET', 3: u'IMPLINK', 4: u'PUP',
    5: u'CHAOS', 6: u'NS', 8: u'ECMA', 9: u'DATAKIT', 10: u'CCITT',
    11: u'SNA', 12: u'DECnet', 13: u'DLI', 14: u'LAT', 15: u'HYLINK',
    16: u'APPLETALK', 19: u'OSI', 23: u'IPX', 24: u'ROUTE',
    25: u'LINK', 26: u'INET6', 27: u'KEY', 500: u'NETBIOS',
    501: u'ISO', 502: u'XTP', 503: u'COIP', 504: u'CNT', 505: u'RTIP',
    506: u'SIP', 507: u'PIP', 508: u'ISDN', 509: u'E164',
    510: u'NATM', 511: u'ATM', 512: u'NETGRAPH', 513: u'SLOW',
    514: u'CLUSTER', 515: u'ARP', 516: u'BLUETOOTH'}

# Text representation of the audit event (/etc/security/audit_event)
# Depends on the Mac OS X version.
BSM_AUDIT_EVENT = {
    0: u'indir system call',
    1: u'exit(2)',
    2: u'fork(2)',
    3: u'open(2) - attr only',
    4: u'creat(2)',
    5: u'link(2)',
    6: u'unlink(2)',
    7: u'exec(2)',
    8: u'chdir(2)',
    9: u'mknod(2)',
    10: u'chmod(2)',
    11: u'chown(2)',
    12: u'umount(2) - old version',
    13: u'junk',
    14: u'access(2)',
    15: u'kill(2)',
    16: u'stat(2)',
    17: u'lstat(2)',
    18: u'acct(2)',
    19: u'mctl(2)',
    20: u'reboot(2)',
    21: u'symlink(2)',
    22: u'readlink(2)',
    23: u'execve(2)',
    24: u'chroot(2)',
    25: u'vfork(2)',
    26: u'setgroups(2)',
    27: u'setpgrp(2)',
    28: u'swapon(2)',
    29: u'sethostname(2)',
    30: u'fcntl(2)',
    31: u'setpriority(2)',
    32: u'connect(2)',
    33: u'accept(2)',
    34: u'bind(2)',
    35: u'setsockopt(2)',
    36: u'vtrace(2)',
    37: u'settimeofday(2)',
    38: u'fchown(2)',
    39: u'fchmod(2)',
    40: u'setreuid(2)',
    41: u'setregid(2)',
    42: u'rename(2)',
    43: u'truncate(2)',
    44: u'ftruncate(2)',
    45: u'flock(2)',
    46: u'shutdown(2)',
    47: u'mkdir(2)',
    48: u'rmdir(2)',
    49: u'utimes(2)',
    50: u'adjtime(2)',
    51: u'setrlimit(2)',
    52: u'killpg(2)',
    53: u'nfs_svc(2)',
    54: u'statfs(2)',
    55: u'fstatfs(2)',
    56: u'unmount(2)',
    57: u'async_daemon(2)',
    58: u'nfs_getfh(2)',
    59: u'setdomainname(2)',
    60: u'quotactl(2)',
    61: u'exportfs(2)',
    62: u'mount(2)',
    63: u'semsys(2)',
    64: u'msgsys(2)',
    65: u'shmsys(2)',
    66: u'bsmsys(2)',
    67: u'rfssys(2)',
    68: u'fchdir(2)',
    69: u'fchroot(2)',
    70: u'vpixsys(2)',
    71: u'pathconf(2)',
    72: u'open(2) - read',
    73: u'open(2) - read,creat',
    74: u'open(2) - read,trunc',
    75: u'open(2) - read,creat,trunc',
    76: u'open(2) - write',
    77: u'open(2) - write,creat',
    78: u'open(2) - write,trunc',
    79: u'open(2) - write,creat,trunc',
    80: u'open(2) - read,write',
    81: u'open(2) - read,write,creat',
    82: u'open(2) - read,write,trunc',
    83: u'open(2) - read,write,creat,trunc',
    84: u'msgctl(2) - illegal command',
    85: u'msgctl(2) - IPC_RMID command',
    86: u'msgctl(2) - IPC_SET command',
    87: u'msgctl(2) - IPC_STAT command',
    88: u'msgget(2)',
    89: u'msgrcv(2)',
    90: u'msgsnd(2)',
    91: u'shmctl(2) - illegal command',
    92: u'shmctl(2) - IPC_RMID command',
    93: u'shmctl(2) - IPC_SET command',
    94: u'shmctl(2) - IPC_STAT command',
    95: u'shmget(2)',
    96: u'shmat(2)',
    97: u'shmdt(2)',
    98: u'semctl(2) - illegal command',
    99: u'semctl(2) - IPC_RMID command',
    100: u'semctl(2) - IPC_SET command',
    101: u'semctl(2) - IPC_STAT command',
    102: u'semctl(2) - GETNCNT command',
    103: u'semctl(2) - GETPID command',
    104: u'semctl(2) - GETVAL command',
    105: u'semctl(2) - GETALL command',
    106: u'semctl(2) - GETZCNT command',
    107: u'semctl(2) - SETVAL command',
    108: u'semctl(2) - SETALL command',
    109: u'semget(2)',
    110: u'semop(2)',
    111: u'process dumped core',
    112: u'close(2)',
    113: u'system booted',
    114: u'async_daemon(2) exited',
    115: u'nfssvc(2) exited',
    128: u'writel(2)',
    129: u'writevl(2)',
    130: u'getauid(2)',
    131: u'setauid(2)',
    132: u'getaudit(2)',
    133: u'setaudit(2)',
    134: u'getuseraudit(2)',
    135: u'setuseraudit(2)',
    136: u'auditsvc(2)',
    137: u'audituser(2)',
    138: u'auditon(2)',
    139: u'auditon(2) - GETTERMID command',
    140: u'auditon(2) - SETTERMID command',
    141: u'auditon(2) - GPOLICY command',
    142: u'auditon(2) - SPOLICY command',
    143: u'auditon(2) - GESTATE command',
    144: u'auditon(2) - SESTATE command',
    145: u'auditon(2) - GQCTRL command',
    146: u'auditon(2) - SQCTRL command',
    147: u'getkernstate(2)',
    148: u'setkernstate(2)',
    149: u'getportaudit(2)',
    150: u'auditstat(2)',
    151: u'revoke(2)',
    152: u'Solaris AUE_MAC',
    153: u'enter prom',
    154: u'exit prom',
    155: u'Solaris AUE_IFLOAT',
    156: u'Solaris AUE_PFLOAT',
    157: u'Solaris AUE_UPRIV',
    158: u'ioctl(2)',
    173: u'one-sided session record',
    174: u'msggetl(2)',
    175: u'msgrcvl(2)',
    176: u'msgsndl(2)',
    177: u'semgetl(2)',
    178: u'shmgetl(2)',
    183: u'socket(2)',
    184: u'sendto(2)',
    185: u'pipe(2)',
    186: u'socketpair(2)',
    187: u'send(2)',
    188: u'sendmsg(2)',
    189: u'recv(2)',
    190: u'recvmsg(2)',
    191: u'recvfrom(2)',
    192: u'read(2)',
    193: u'getdents(2)',
    194: u'lseek(2)',
    195: u'write(2)',
    196: u'writev(2)',
    197: u'nfs server',
    198: u'readv(2)',
    199: u'Solaris old stat(2)',
    200: u'setuid(2)',
    201: u'old stime(2)',
    202: u'old utime(2)',
    203: u'old nice(2)',
    204: u'Solaris old setpgrp(2)',
    205: u'setgid(2)',
    206: u'readl(2)',
    207: u'readvl(2)',
    208: u'fstat(2)',
    209: u'dup2(2)',
    210: u'mmap(2)',
    211: u'audit(2)',
    212: u'Solaris priocntlsys(2)',
    213: u'munmap(2)',
    214: u'setegid(2)',
    215: u'seteuid(2)',
    216: u'putmsg(2)',
    217: u'getmsg(2)',
    218: u'putpmsg(2)',
    219: u'getpmsg(2)',
    220: u'audit system calls place holder',
    221: u'auditon(2) - get kernel mask',
    222: u'auditon(2) - set kernel mask',
    223: u'auditon(2) - get cwd',
    224: u'auditon(2) - get car',
    225: u'auditon(2) - get audit statistics',
    226: u'auditon(2) - reset audit statistics',
    227: u'auditon(2) - set mask per uid',
    228: u'auditon(2) - set mask per session ID',
    229: u'auditon(2) - get audit state',
    230: u'auditon(2) - set audit state',
    231: u'auditon(2) - get event class',
    232: u'auditon(2) - set event class',
    233: u'utssys(2) - fusers',
    234: u'statvfs(2)',
    235: u'xstat(2)',
    236: u'lxstat(2)',
    237: u'lchown(2)',
    238: u'memcntl(2)',
    239: u'sysinfo(2)',
    240: u'xmknod(2)',
    241: u'fork1(2)',
    242: u'modctl(2) system call place holder',
    243: u'modctl(2) - load module',
    244: u'modctl(2) - unload module',
    245: u'modctl(2) - configure module',
    246: u'modctl(2) - bind module',
    247: u'getmsg-accept',
    248: u'putmsg-connect',
    249: u'putmsg-send',
    250: u'getmsg-receive',
    251: u'acl(2) - SETACL comand',
    252: u'facl(2) - SETACL command',
    253: u'doorfs(2) - system call place holder',
    254: u'doorfs(2) - DOOR_CALL',
    255: u'doorfs(2) - DOOR_RETURN',
    256: u'doorfs(2) - DOOR_CREATE',
    257: u'doorfs(2) - DOOR_REVOKE',
    258: u'doorfs(2) - DOOR_INFO',
    259: u'doorfs(2) - DOOR_CRED',
    260: u'doorfs(2) - DOOR_BIND',
    261: u'doorfs(2) - DOOR_UNBIND',
    262: u'p_online(2)',
    263: u'processor_bind(2)',
    264: u'inst_sync(2)',
    265: u'configure socket',
    266: u'setaudit_addr(2)',
    267: u'getaudit_addr(2)',
    268: u'Solaris umount(2)',
    269: u'fsat(2) - place holder',
    270: u'openat(2) - read',
    271: u'openat(2) - read,creat',
    272: u'openat(2) - read,trunc',
    273: u'openat(2) - read,creat,trunc',
    274: u'openat(2) - write',
    275: u'openat(2) - write,creat',
    276: u'openat(2) - write,trunc',
    277: u'openat(2) - write,creat,trunc',
    278: u'openat(2) - read,write',
    279: u'openat(2) - read,write,create',
    280: u'openat(2) - read,write,trunc',
    281: u'openat(2) - read,write,creat,trunc',
    282: u'renameat(2)',
    283: u'fstatat(2)',
    284: u'fchownat(2)',
    285: u'futimesat(2)',
    286: u'unlinkat(2)',
    287: u'clock_settime(2)',
    288: u'ntp_adjtime(2)',
    289: u'setppriv(2)',
    290: u'modctl(2) - configure device policy',
    291: u'modctl(2) - configure additional privilege',
    292: u'kernel cryptographic framework',
    293: u'configure kernel SSL',
    294: u'brandsys(2)',
    295: u'Add IPsec policy rule',
    296: u'Delete IPsec policy rule',
    297: u'Clone IPsec policy',
    298: u'Flip IPsec policy',
    299: u'Flush IPsec policy rules',
    300: u'Update IPsec algorithms',
    301: u'portfs',
    302: u'ptrace(2)',
    303: u'chflags(2)',
    304: u'fchflags(2)',
    305: u'profil(2)',
    306: u'ktrace(2)',
    307: u'setlogin(2)',
    308: u'reboot(2)',
    309: u'revoke(2)',
    310: u'umask(2)',
    311: u'mprotect(2)',
    312: u'setpriority(2)',
    313: u'settimeofday(2)',
    314: u'flock(2)',
    315: u'mkfifo(2)',
    316: u'poll(2)',
    317: u'socketpair(2)',
    318: u'futimes(2)',
    319: u'setsid(2)',
    320: u'setprivexec(2)',
    321: u'nfssvc(2)',
    322: u'getfh(2)',
    323: u'quotactl(2)',
    324: u'add_profil()',
    325: u'kdebug_trace()',
    326: u'fstat(2)',
    327: u'fpathconf(2)',
    328: u'getdirentries(2)',
    329: u'truncate(2)',
    330: u'ftruncate(2)',
    331: u'sysctl(3)',
    332: u'mlock(2)',
    333: u'munlock(2)',
    334: u'undelete(2)',
    335: u'getattrlist()',
    336: u'setattrlist()',
    337: u'getdirentriesattr()',
    338: u'exchangedata()',
    339: u'searchfs()',
    340: u'minherit(2)',
    341: u'semconfig()',
    342: u'sem_open(2)',
    343: u'sem_close(2)',
    344: u'sem_unlink(2)',
    345: u'shm_open(2)',
    346: u'shm_unlink(2)',
    347: u'load_shared_file()',
    348: u'reset_shared_file()',
    349: u'new_system_share_regions()',
    350: u'pthread_kill(2)',
    351: u'pthread_sigmask(2)',
    352: u'auditctl(2)',
    353: u'rfork(2)',
    354: u'lchmod(2)',
    355: u'swapoff(2)',
    356: u'init_process()',
    357: u'map_fd()',
    358: u'task_for_pid()',
    359: u'pid_for_task()',
    360: u'sysctl() - non-admin',
    361: u'copyfile()',
    43001: u'getfsstat(2)',
    43002: u'ptrace(2)',
    43003: u'chflags(2)',
    43004: u'fchflags(2)',
    43005: u'profil(2)',
    43006: u'ktrace(2)',
    43007: u'setlogin(2)',
    43008: u'revoke(2)',
    43009: u'umask(2)',
    43010: u'mprotect(2)',
    43011: u'mkfifo(2)',
    43012: u'poll(2)',
    43013: u'futimes(2)',
    43014: u'setsid(2)',
    43015: u'setprivexec(2)',
    43016: u'add_profil()',
    43017: u'kdebug_trace()',
    43018: u'fstat(2)',
    43019: u'fpathconf(2)',
    43020: u'getdirentries(2)',
    43021: u'sysctl(3)',
    43022: u'mlock(2)',
    43023: u'munlock(2)',
    43024: u'undelete(2)',
    43025: u'getattrlist()',
    43026: u'setattrlist()',
    43027: u'getdirentriesattr()',
    43028: u'exchangedata()',
    43029: u'searchfs()',
    43030: u'minherit(2)',
    43031: u'semconfig()',
    43032: u'sem_open(2)',
    43033: u'sem_close(2)',
    43034: u'sem_unlink(2)',
    43035: u'shm_open(2)',
    43036: u'shm_unlink(2)',
    43037: u'load_shared_file()',
    43038: u'reset_shared_file()',
    43039: u'new_system_share_regions()',
    43040: u'pthread_kill(2)',
    43041: u'pthread_sigmask(2)',
    43042: u'auditctl(2)',
    43043: u'rfork(2)',
    43044: u'lchmod(2)',
    43045: u'swapoff(2)',
    43046: u'init_process()',
    43047: u'map_fd()',
    43048: u'task_for_pid()',
    43049: u'pid_for_task()',
    43050: u'sysctl() - non-admin',
    43051: u'copyfile(2)',
    43052: u'lutimes(2)',
    43053: u'lchflags(2)',
    43054: u'sendfile(2)',
    43055: u'uselib(2)',
    43056: u'getresuid(2)',
    43057: u'setresuid(2)',
    43058: u'getresgid(2)',
    43059: u'setresgid(2)',
    43060: u'wait4(2)',
    43061: u'lgetfh(2)',
    43062: u'fhstatfs(2)',
    43063: u'fhopen(2)',
    43064: u'fhstat(2)',
    43065: u'jail(2)',
    43066: u'eaccess(2)',
    43067: u'kqueue(2)',
    43068: u'kevent(2)',
    43069: u'fsync(2)',
    43070: u'nmount(2)',
    43071: u'bdflush(2)',
    43072: u'setfsuid(2)',
    43073: u'setfsgid(2)',
    43074: u'personality(2)',
    43075: u'getscheduler(2)',
    43076: u'setscheduler(2)',
    43077: u'prctl(2)',
    43078: u'getcwd(2)',
    43079: u'capget(2)',
    43080: u'capset(2)',
    43081: u'pivot_root(2)',
    43082: u'rtprio(2)',
    43083: u'sched_getparam(2)',
    43084: u'sched_setparam(2)',
    43085: u'sched_get_priority_max(2)',
    43086: u'sched_get_priority_min(2)',
    43087: u'sched_rr_get_interval(2)',
    43088: u'acl_get_file(2)',
    43089: u'acl_set_file(2)',
    43090: u'acl_get_fd(2)',
    43091: u'acl_set_fd(2)',
    43092: u'acl_delete_file(2)',
    43093: u'acl_delete_fd(2)',
    43094: u'acl_aclcheck_file(2)',
    43095: u'acl_aclcheck_fd(2)',
    43096: u'acl_get_link(2)',
    43097: u'acl_set_link(2)',
    43098: u'acl_delete_link(2)',
    43099: u'acl_aclcheck_link(2)',
    43100: u'sysarch(2)',
    43101: u'extattrctl(2)',
    43102: u'extattr_get_file(2)',
    43103: u'extattr_set_file(2)',
    43104: u'extattr_list_file(2)',
    43105: u'extattr_delete_file(2)',
    43106: u'extattr_get_fd(2)',
    43107: u'extattr_set_fd(2)',
    43108: u'extattr_list_fd(2)',
    43109: u'extattr_delete_fd(2)',
    43110: u'extattr_get_link(2)',
    43111: u'extattr_set_link(2)',
    43112: u'extattr_list_link(2)',
    43113: u'extattr_delete_link(2)',
    43114: u'kenv(8)',
    43115: u'jail_attach(2)',
    43116: u'sysctl(3)',
    43117: u'linux ioperm',
    43118: u'readdir(3)',
    43119: u'linux iopl',
    43120: u'linux vm86',
    43121: u'mac_get_proc(2)',
    43122: u'mac_set_proc(2)',
    43123: u'mac_get_fd(2)',
    43124: u'mac_get_file(2)',
    43125: u'mac_set_fd(2)',
    43126: u'mac_set_file(2)',
    43127: u'mac_syscall(2)',
    43128: u'mac_get_pid(2)',
    43129: u'mac_get_link(2)',
    43130: u'mac_set_link(2)',
    43131: u'mac_execve(2)',
    43132: u'getpath_fromfd(2)',
    43133: u'getpath_fromaddr(2)',
    43134: u'mq_open(2)',
    43135: u'mq_setattr(2)',
    43136: u'mq_timedreceive(2)',
    43137: u'mq_timedsend(2)',
    43138: u'mq_notify(2)',
    43139: u'mq_unlink(2)',
    43140: u'listen(2)',
    43141: u'mlockall(2)',
    43142: u'munlockall(2)',
    43143: u'closefrom(2)',
    43144: u'fexecve(2)',
    43145: u'faccessat(2)',
    43146: u'fchmodat(2)',
    43147: u'linkat(2)',
    43148: u'mkdirat(2)',
    43149: u'mkfifoat(2)',
    43150: u'mknodat(2)',
    43151: u'readlinkat(2)',
    43152: u'symlinkat(2)',
    43153: u'mac_getfsstat(2)',
    43154: u'mac_get_mount(2)',
    43155: u'mac_get_lcid(2)',
    43156: u'mac_get_lctx(2)',
    43157: u'mac_set_lctx(2)',
    43158: u'mac_mount(2)',
    43159: u'getlcid(2)',
    43160: u'setlcid(2)',
    43161: u'taskname_for_pid()',
    43162: u'access_extended(2)',
    43163: u'chmod_extended(2)',
    43164: u'fchmod_extended(2)',
    43165: u'fstat_extended(2)',
    43166: u'lstat_extended(2)',
    43167: u'mkdir_extended(2)',
    43168: u'mkfifo_extended(2)',
    43169: u'open_extended(2) - attr only',
    43170: u'open_extended(2) - read',
    43171: u'open_extended(2) - read,creat',
    43172: u'open_extended(2) - read,trunc',
    43173: u'open_extended(2) - read,creat,trunc',
    43174: u'open_extended(2) - write',
    43175: u'open_extended(2) - write,creat',
    43176: u'open_extended(2) - write,trunc',
    43177: u'open_extended(2) - write,creat,trunc',
    43178: u'open_extended(2) - read,write',
    43179: u'open_extended(2) - read,write,creat',
    43180: u'open_extended(2) - read,write,trunc',
    43181: u'open_extended(2) - read,write,creat,trunc',
    43182: u'stat_extended(2)',
    43183: u'umask_extended(2)',
    43184: u'openat(2) - attr only',
    43185: u'posix_openpt(2)',
    43186: u'cap_new(2)',
    43187: u'cap_getrights(2)',
    43188: u'cap_enter(2)',
    43189: u'cap_getmode(2)',
    43190: u'posix_spawn(2)',
    43191: u'fsgetpath(2)',
    43192: u'pread(2)',
    43193: u'pwrite(2)',
    43194: u'fsctl()',
    43195: u'ffsctl()',
    43196: u'lpathconf(2)',
    43197: u'pdfork(2)',
    43198: u'pdkill(2)',
    43199: u'pdgetpid(2)',
    43200: u'pdwait(2)',
    44901: u'session start',
    44902: u'session update',
    44903: u'session end',
    44904: u'session close',
    6144: u'at-create atjob',
    6145: u'at-delete atjob (at or atrm)',
    6146: u'at-permission',
    6147: u'cron-invoke',
    6148: u'crontab-crontab created',
    6149: u'crontab-crontab deleted',
    6150: u'crontab-permission',
    6151: u'inetd connection',
    6152: u'login - local',
    6153: u'logout - local',
    6154: u'login - telnet',
    6155: u'login - rlogin',
    6156: u'mount',
    6157: u'unmount',
    6158: u'rsh access',
    6159: u'su(1)',
    6160: u'system halt',
    6161: u'system reboot',
    6162: u'rexecd',
    6163: u'passwd',
    6164: u'rexd',
    6165: u'ftp access',
    6166: u'init',
    6167: u'uadmin',
    6168: u'system shutdown',
    6170: u'crontab-modify',
    6171: u'ftp logout',
    6172: u'login - ssh',
    6173: u'role login',
    6180: u' profile command',
    6181: u'add filesystem',
    6182: u'delete filesystem',
    6183: u'modify filesystem',
    6200: u'allocate-device success',
    6201: u'allocate-device failure',
    6202: u'deallocate-device success',
    6203: u'deallocate-device failure',
    6204: u'allocate-list devices success',
    6205: u'allocate-list devices failure',
    6207: u'create user',
    6208: u'modify user',
    6209: u'delete user',
    6210: u'disable user',
    6211: u'enable user',
    6212: u'newgrp login',
    6213: u'admin login',
    6214: u'authenticated kadmind request',
    6215: u'unauthenticated kadmind req',
    6216: u'kdc authentication svc request',
    6217: u'kdc tkt-grant svc request',
    6218: u'kdc tgs 2ndtkt mismtch',
    6219: u'kdc tgs issue alt tgt',
    6300: u'sudo(1)',
    6501: u'modify password',
    6511: u'create group',
    6512: u'delete group',
    6513: u'modify group',
    6514: u'add to group',
    6515: u'remove from group',
    6521: u'revoke object priv',
    6600: u'loginwindow login',
    6601: u'loginwindow logout',
    7000: u'user authentication',
    7001: u'SecSrvr connection setup',
    7002: u'SecSrvr AuthEngine',
    7003: u'SecSrvr authinternal mech',
    32800: u'OpenSSH login',
    45000: u'audit startup',
    45001: u'audit shutdown',
    45014: u'modify password',
    45015: u'create group',
    45016: u'delete group',
    45017: u'modify group',
    45018: u'add to group',
    45019: u'remove from group',
    45020: u'revoke object priv',
    45021: u'loginwindow login',
    45022: u'loginwindow logout',
    45023: u'user authentication',
    45024: u'SecSrvr connection setup',
    45025: u'SecSrvr AuthEngine',
    45026: u'SecSrvr authinternal mech',
    45027: u'Calife',
    45028: u'sudo(1)',
    45029: u'audit crash recovery',
    45030: u'SecSrvr AuthMechanism',
    45031: u'Security Assessment'
}


##### STRUCTURES #####


IPV4_STRUCT = construct.UBInt32('ipv4')

IPV6_STRUCT = construct.Struct(
  'ipv6', construct.UBInt64('high'), construct.UBInt64('low'))

# TODO: Implement the following tokens:
#       au_to_ipc_perm, au_to_sock_unix

# Tested structures.
# INFO: I have ommited the ID in the structures declaration.
#       I used the BSM_TYPE first to read the ID, and then, the structure.
# Tokens always start with an ID value that identifies their token
# type and subsequent structure.
# token type that we are going to read, the token structure.
BSM_TYPE = construct.UBInt8('token_id')

# Data type structures.
BSM_TOKEN_DATA_CHAR = construct.String('value', 1)
BSM_TOKEN_DATA_SHORT = construct.UBInt16('value')
BSM_TOKEN_DATA_INTEGER = construct.UBInt32('value')

# Common structure used by other structures.
# audit_uid: integer, uid that generates the entry.
# effective_uid: integer, the permission user used.
# effective_gid: integer, the permission group used.
# real_uid: integer, user id of the user that execute the process.
# real_gid: integer, group id of the group that execute the process.
# pid: integer, identification number of the process.
# session_id: unknown, need research.
BSM_TOKEN_SUBJECT_SHORT = construct.Struct(
    'subject_data',
    construct.UBInt32('audit_uid'),
    construct.UBInt32('effective_uid'),
    construct.UBInt32('effective_gid'),
    construct.UBInt32('real_uid'),
    construct.UBInt32('real_gid'),
    construct.UBInt32('pid'),
    construct.UBInt32('session_id'))

# Common structure used by other structures.
# Identify the kind of inet (IPv4 or IPv6)
# TODO: instead of 16, AU_IPv6 must be used.
BSM_IP_TYPE_SHORT = construct.Struct(
    'bsm_ip_type_short',
    construct.UBInt32('net_type'),
    construct.IfThenElse(
    'ip_addr', lambda ctx: ctx['net_type'] == 16,
        IPV6_STRUCT,
        IPV4_STRUCT))
# Initial fields structure used by header structures.
# length: integer, the lenght of the entry, equal to trailer (doc: length).
# version: integer, version of BSM (AUDIT_HEADER_VERSION).
# event_type: integer, the type of event (/etc/security/audit_event).
# modifier: integer, unknown, need research (It is always 0).
BSM_HEADER = construct.Struct(
    'bsm_header',
    construct.UBInt32('length'),
    construct.UBInt8('version'),
    construct.UBInt16('event_type'),
    construct.UBInt16('modifier'))

# First token of one entry.
# timestamp: integer, Epoch timestamp of the entry.
# microsecond: integer, the microsecond of the entry.
BSM_HEADER32 = construct.Struct(
    'bsm_header32',
    BSM_HEADER,
    construct.UBInt32('timestamp'),
    construct.UBInt32('microsecond'))

BSM_HEADER64 = construct.Struct(
    'bsm_header32',
    BSM_HEADER,
    construct.UBInt64('timestamp'),
    construct.UBInt64('microsecond'))

BSM_HEADER32_EX = construct.Struct(
    'header',
    BSM_HEADER,
    BSM_IP_TYPE_SHORT,
    construct.UBInt32('timestamp'),
    construct.UBInt32('microsecond'))

# Token TEXT, provides extra information.
BSM_TOKEN_TEXT = construct.PascalString(
    'value', length_field = construct.UBInt16('length'))

# Path of the executable.
BSM_TOKEN_PATH = BSM_TOKEN_TEXT

# Identified the end of the record (follow by TRAILER).
# status: integer that identifies the status of the exit (BSM_ERRORS).
# return: returned value from the operation.
BSM_TOKEN_RETURN32 = construct.Struct(
   'bsm_token_return32',
    construct.UBInt8('status'),
    construct.UBInt32('return_value'))

BSM_TOKEN_RETURN64 = construct.Struct(
    'bsm_token_return64',
    construct.UBInt8('status'),
    construct.UBInt64('return_value'))

# Identified the number of bytes that was written.
# magic: 2 bytes that identifes the TRAILER (BSM_TOKEN_TRAILER_MAGIC).
# length: integer that has the number of bytes from the entry size.
BSM_TOKEN_TRAILER = construct.Struct(
    'bsm_token_trailer',
     construct.UBInt16('magic'),
     construct.UBInt32('record_length'))

# A 32-bits argument.
# num_arg: the number of the argument.
# name_arg: the argument's name.
# text: the string value of the argument.
BSM_TOKEN_ARGUMENT32 = construct.Struct(
    'bsm_token_argument32',
    construct.UBInt8('num_arg'),
    construct.UBInt32('name_arg'),
    BSM_TOKEN_TEXT)

# A 64-bits argument.
# num_arg: integer, the number of the argument.
# name_arg: text, the argument's name.
# text: the string value of the argument.
BSM_TOKEN_ARGUMENT64 = construct.Struct(
    'bsm_token_argument64',
    construct.UBInt8('num_arg'),
    construct.UBInt64('name_arg'),
    BSM_TOKEN_TEXT)

# Identify an user.
# terminal_id: unknown, research needed.
# terminal_addr: unknown, research needed.
BSM_TOKEN_SUBJECT32 = construct.Struct(
    'bsm_token_subject32',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt32('terminal_port'),
    IPV4_STRUCT)

# Identify an user using a extended Token.
# terminal_port: unknown, need research.
# net_type: unknown, need research.
BSM_TOKEN_SUBJECT32_EX = construct.Struct(
    'bsm_token_subject32_ex',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt32('terminal_port'),
    BSM_IP_TYPE_SHORT)

# au_to_opaque // AUT_OPAQUE
BSM_TOKEN_OPAQUE = BSM_TOKEN_TEXT

# au_to_seq // AUT_SEQ
BSM_TOKEN_SEQUENCE = BSM_TOKEN_DATA_INTEGER

# Program execution with options.
# For each argument we are going to have a string+ "\x00".
# Example: [00 00 00 02][41 42 43 00 42 42 00]
#          2 Arguments, Arg1: [414243] Arg2: [4242].
BSM_TOKEN_EXEC_ARGUMENTS = construct.UBInt32('number_arguments')
BSM_TOKEN_EXEC_ARGUMENT = construct.macros.CString('text')

# au_to_in_addr // AUT_IN_ADDR:
BSM_TOKEN_ADDR = IPV4_STRUCT

# au_to_in_addr_ext // AUT_IN_ADDR_EX:
BSM_TOKEN_ADDR_EXT = construct.Struct(
    'bsm_token_addr_ext',
    construct.UBInt32('net_type'),
    IPV6_STRUCT)

# au_to_ip // AUT_IP:
# TODO: parse this header in the correct way.
BSM_TOKEN_IP = construct.String('binary_ipv4_add', 20)

# au_to_ipc // AUT_IPC:
BSM_TOKEN_IPC = construct.Struct(
    'bsm_token_ipc',
    construct.UBInt8('object_type'),
    construct.UBInt32('object_id'))

# au_to_iport // AUT_IPORT:
BSM_TOKEN_PORT = construct.UBInt16('port_number')

# au_to_file // AUT_OTHER_FILE32:
BSM_TOKEN_FILE = construct.Struct(
    'bsm_token_file',
    construct.UBInt32('timestamp'),
    construct.UBInt32('microsecond'),
    construct.PascalString(
    'file_name', length_field = construct.UBInt16('length')))

# au_to_subject64 // AUT_SUBJECT64:
BSM_TOKEN_SUBJECT64 = construct.Struct(
    'bsm_token_subject64',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt64('terminal_port'),
    IPV4_STRUCT)

# au_to_subject64_ex // AU_IPv4:
BSM_TOKEN_SUBJECT64_EX = construct.Struct(
    'bsm_token_subject64_ex',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt32('terminal_port'),
    construct.UBInt32('terminal_type'),
    BSM_IP_TYPE_SHORT)

# au_to_process32 // AUT_PROCESS32:
BSM_TOKEN_PROCESS32 = construct.Struct(
    'bsm_token_process32',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt32('terminal_port'),
    IPV4_STRUCT)

# au_to_process64 // AUT_PROCESS32:
BSM_TOKEN_PROCESS64 = construct.Struct(
    'bsm_token_process64',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt64('terminal_port'),
    IPV4_STRUCT)

# au_to_process32_ex // AUT_PROCESS32_EX:
BSM_TOKEN_PROCESS32_EX = construct.Struct(
    'bsm_token_process32_ex',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt32('terminal_port'),
    BSM_IP_TYPE_SHORT)

# au_to_process64_ex // AUT_PROCESS64_EX:
BSM_TOKEN_PROCESS64_EX = construct.Struct(
    'bsm_token_process32_ex',
    BSM_TOKEN_SUBJECT_SHORT,
    construct.UBInt64('terminal_port'),
    BSM_IP_TYPE_SHORT)

# au_to_sock_inet32 // AUT_SOCKINET32:
BSM_TOKEN_AUT_SOCKINET32 = construct.Struct(
    'bsm_token_aut_sockinet32',
    construct.UBInt16('net_type'),
    construct.UBInt16('port_number'),
    IPV4_STRUCT)

# Info: checked against the source code of XNU, but not against
#       real BSM file.
BSM_TOKEN_AUT_SOCKINET128 = construct.Struct(
    'bsm_token_aut_sockinet128',
     construct.UBInt16('net_type'),
    construct.UBInt16('port_number'),
    IPV6_STRUCT)

# au_to_socket_ex // AUT_SOCKET_EX
# TODO: Change the 26 for unixbsm.BSM_PROTOCOLS.INET6.
BSM_TOKEN_AUT_SOCKINET32_EX = construct.Struct(
    'bsm_token_aut_sockinet32_ex',
    construct.UBInt16('socket_domain'),
    construct.UBInt16('socket_type'),
    construct.IfThenElse(
        'structure_addr_port',
        lambda ctx: ctx['socket_domain'] == 26,
        construct.Struct('addr_type',
            construct.UBInt16('ip_type'),
            construct.UBInt16('source_port'),
            construct.UBInt64('saddr_high'),
            construct.UBInt64('saddr_low'),
            construct.UBInt16('destination_port'),
            construct.UBInt64('daddr_high'),
            construct.UBInt64('daddr_low')),
        construct.Struct('addr_type',
            construct.UBInt16('ip_type'),
            construct.UBInt16('source_port'),
            construct.UBInt32('source_address'),
            construct.UBInt16('destination_port'),
            construct.UBInt32('destination_address'))))

# au_to_data // au_to_data
# how to print: BSM_TOKEN_DATA_PRINT.
# type: BSM_TOKEN_DATA_TYPE.
# unit_count: number of type values.
# BSM_TOKEN_DATA has a end field = type * unit_count
BSM_TOKEN_DATA = construct.Struct(
    'bsm_token_data',
    construct.UBInt8('how_to_print'),
    construct.UBInt8('data_type'),
    construct.UBInt8('unit_count'))

# au_to_attr32 // AUT_ATTR32
BSM_TOKEN_ATTR32 = construct.Struct(
    'bsm_token_attr32',
    construct.UBInt32('file_mode'),
    construct.UBInt32('uid'),
    construct.UBInt32('gid'),
    construct.UBInt32('file_system_id'),
    construct.UBInt64('file_system_node_id'),
    construct.UBInt32('device'))

# au_to_attr64 // AUT_ATTR64
BSM_TOKEN_ATTR64 = construct.Struct(
    'bsm_token_attr32',
    construct.UBInt32('file_mode'),
    construct.UBInt32('uid'),
    construct.UBInt32('gid'),
    construct.UBInt32('file_system_id'),
    construct.UBInt64('file_system_node_id'),
    construct.UBInt64('device'))

# au_to_exit // AUT_EXIT
BSM_TOKEN_EXIT = construct.Struct(
    'bsm_token_exit',
    construct.UBInt32('status'),
    construct.UBInt32('return_value'))

# au_to_newgroups // AUT_NEWGROUPS
# INFO: we must read BSM_TOKEN_DATA_INTEGER for each group.
BSM_TOKEN_GROUPS = construct.UBInt16('group_number')

# au_to_exec_env == au_to_exec_args
BSM_TOKEN_EXEC_ENV = BSM_TOKEN_EXEC_ARGUMENTS

# au_to_zonename //AUT_ZONENAME
BSM_TOKEN_ZONENAME = BSM_TOKEN_TEXT

#### TOKEN ID ####
# Only the checked structures are been added to the valid structures lists.
BSM_TYPE_LIST = {
      17: ['BSM_TOKEN_FILE', BSM_TOKEN_FILE],
      19: ['BSM_TOKEN_TRAILER', BSM_TOKEN_TRAILER],
      20: ['BSM_HEADER32', BSM_HEADER32],
      21: ['BSM_HEADER64', BSM_HEADER64],
      33: ['BSM_TOKEN_DATA', BSM_TOKEN_DATA],
      34: ['BSM_TOKEN_IPC', BSM_TOKEN_IPC],
      35: ['BSM_TOKEN_PATH', BSM_TOKEN_PATH],
      36: ['BSM_TOKEN_SUBJECT32', BSM_TOKEN_SUBJECT32],
      38: ['BSM_TOKEN_PROCESS32', BSM_TOKEN_PROCESS32],
      39: ['BSM_TOKEN_RETURN32', BSM_TOKEN_RETURN32],
      40: ['BSM_TOKEN_TEXT', BSM_TOKEN_TEXT],
      41: ['BSM_TOKEN_OPAQUE', BSM_TOKEN_OPAQUE],
      42: ['BSM_TOKEN_ADDR', BSM_TOKEN_ADDR],
      43: ['BSM_TOKEN_IP', BSM_TOKEN_IP],
      44: ['BSM_TOKEN_PORT', BSM_TOKEN_PORT],
      45: ['BSM_TOKEN_ARGUMENT32', BSM_TOKEN_ARGUMENT32],
      47: ['BSM_TOKEN_SEQUENCE', BSM_TOKEN_SEQUENCE],
      49: ['BSM_TOKEN_ATTR32', BSM_TOKEN_ATTR32],
      52: ['BSM_TOKEN_GROUPS', BSM_TOKEN_GROUPS],
      59: ['BSM_TOKEN_GROUPS', BSM_TOKEN_GROUPS],
      60: ['BSM_TOKEN_EXEC_ARGUMENTS', BSM_TOKEN_EXEC_ARGUMENTS],
      61: ['BSM_TOKEN_EXEC_ENV', BSM_TOKEN_EXEC_ENV],
      62: ['BSM_TOKEN_ATTR32', BSM_TOKEN_ATTR32],
      82: ['BSM_TOKEN_EXIT', BSM_TOKEN_EXIT],
      96: ['BSM_TOKEN_ZONENAME', BSM_TOKEN_ZONENAME],
      113: ['BSM_TOKEN_ARGUMENT64', BSM_TOKEN_ARGUMENT64],
      114: ['BSM_TOKEN_RETURN64', BSM_TOKEN_RETURN64],
      115: ['BSM_TOKEN_ATTR64', BSM_TOKEN_ATTR64],
      116: ['BSM_HEADER32_EX', BSM_HEADER32_EX],
      117: ['BSM_TOKEN_SUBJECT64', BSM_TOKEN_SUBJECT64],
      119: ['BSM_TOKEN_PROCESS64', BSM_TOKEN_PROCESS64],
      122: ['BSM_TOKEN_SUBJECT32_EX', BSM_TOKEN_SUBJECT32_EX],
      123: ['BSM_TOKEN_PROCESS32_EX', BSM_TOKEN_PROCESS32_EX],
      124: ['BSM_TOKEN_PROCESS64_EX', BSM_TOKEN_PROCESS64_EX],
      125: ['BSM_TOKEN_SUBJECT64_EX', BSM_TOKEN_SUBJECT64_EX],
      126: ['BSM_TOKEN_ADDR_EXT', BSM_TOKEN_ADDR_EXT],
      127: ['BSM_TOKEN_AUT_SOCKINET32_EX', BSM_TOKEN_AUT_SOCKINET32_EX],
      128: ['BSM_TOKEN_AUT_SOCKINET32', BSM_TOKEN_AUT_SOCKINET32],
      129: ['BSM_TOKEN_AUT_SOCKINET128', BSM_TOKEN_AUT_SOCKINET128]}

#### FUNCTIONS ####
  
# Formating a Token to be printed.
#
# Args:
#   token_id: text name that identificate the Token ID
#   token: the token structure  to be formated.
#   f: the bsm file.
#
# Return:
#   A list with a well formated Token.
def FormatToken(token_id, token, f):
  if token_id not in BSM_TYPE_LIST:
    return u'Type unknown: {0} (0x{1:X})'.format(token_id, token_id)
  bsm_type, _ = BSM_TYPE_LIST.get(token_id, ['', ''])
  if bsm_type == 'BSM_TOKEN_TEXT':
    return u'[{}: {}]'.format(bsm_type, _RawToUTF8(token))
  elif bsm_type == 'BSM_TOKEN_PATH':
    return u'[{}: {}]'.format(bsm_type, _RawToUTF8(token))
  elif (bsm_type == 'BSM_TOKEN_RETURN32' or
      bsm_type == 'BSM_TOKEN_RETURN64' or
      bsm_type == 'BSM_TOKEN_EXIT'):
    return u'[{}: {} ({}), System call status: {}]'.format(
        bsm_type, BSM_ERRORS.get(token.status, 'Unknown'),
        token.status, token.return_value)
  elif (bsm_type == 'BSM_TOKEN_SUBJECT32' or
      bsm_type == 'BSM_TOKEN_SUBJECT64'):
    return (u'[{}: aid({}), euid({}), egid({}), uid({}), gid({}), '
            u'pid({}), session_id({}), terminal_port({}), '
            u'terminal_ip({})]'.format(
                bsm_type,
                token.subject_data.audit_uid,
                token.subject_data.effective_uid,
                token.subject_data.effective_gid,
                token.subject_data.real_uid,
                token.subject_data.real_gid,
                token.subject_data.pid,
                token.subject_data.session_id,
                token.terminal_port,
                _IPv4Format(token.ipv4)))
  elif (bsm_type == 'BSM_TOKEN_SUBJECT32_EX' or
      bsm_type == 'BSM_TOKEN_SUBJECT64_EX'):
    if token.bsm_ip_type_short.net_type == AU_IPv6:
      ip = _IPv6Format(
          token.bsm_ip_type_short.ip_addr.high,
          token.bsm_ip_type_short.ip_addr.low)
    elif token.bsm_ip_type_short.net_type == AU_IPv4:
      ip = _IPv4Format(token.bsm_ip_type_short.ip_addr)
    else:
      ip = 'unknown'
    return (u'[{}: aid({}), euid({}), egid({}), uid({}), gid({}), '
            u'pid({}), session_id({}), terminal_port({}), '
            u'terminal_ip({})]'.format(
                bsm_type,
                token.subject_data.audit_uid,
                token.subject_data.effective_uid,
                token.subject_data.effective_gid,
                token.subject_data.real_uid,
                token.subject_data.real_gid,
                token.subject_data.pid,
                token.subject_data.session_id,
                token.terminal_port, ip))
  elif (bsm_type == 'BSM_TOKEN_ARGUMENT32' or
      bsm_type == 'BSM_TOKEN_ARGUMENT64'):
    return u'[{}: {}({}) is 0x{:X}]'.format(
        bsm_type, _RawToUTF8(token.value),
        token.num_arg, token.name_arg)
  elif (bsm_type == 'BSM_TOKEN_EXEC_ARGUMENTS' or
      bsm_type == 'BSM_TOKEN_EXEC_ENV'):
    arguments = []
    for _ in range(token):
      arguments.append(
          _RawToUTF8(BSM_TOKEN_EXEC_ARGUMENT.parse_stream(
              f)))
    return u'[{}: {}]'.format(bsm_type, u' '.join(arguments))
  elif (bsm_type == 'BSM_TOKEN_ZONENAME'):
    return u'[{}: {}]'.format(bsm_type, _RawToUTF8(token))
  elif bsm_type == 'BSM_TOKEN_AUT_SOCKINET32':
    return (u'[{0}: {1} ({2}) open in port {3}. Address {4}]'.format(
                bsm_type,
                BSM_PROTOCOLS.get(token.net_type, 'UNKNOWN'),
                token.net_type, token.port_number,
                _IPv4Format(token.ipv4)))
  elif bsm_type == 'BSM_TOKEN_AUT_SOCKINET128':
    return u'[{0}: {1} ({2}) open in port {3}. Address {4}]'.format(
        bsm_type,
        BSM_PROTOCOLS.get(token.net_type, 'UNKNOWN'),
        token.net_type, token.port_number,
        _Ipv6Format(token.ipv6.high, token.ipv6.low))
  elif bsm_type == 'BSM_TOKEN_ADDR':
    return u'[{}: {}]'.format(bsm_type, _IPv4Format(token))
  elif bsm_type == 'BSM_TOKEN_IP':
    return u'[IPv4_Header: 0x{}]'.format(token.encode('hex'))
  elif bsm_type == 'BSM_TOKEN_ADDR_EXT':
    return u'[{0}: {1} ({2}). Address {3}]'.format(
        bsm_type,
        BSM_PROTOCOLS.get(token.net_type, 'UNKNOWN'),
        token.net_type, _Ipv6Format(token.ipv6.high, token.ipv6.low))
  elif bsm_type == 'BSM_TOKEN_PORT':
    return u'[{}: {}]'.format(bsm_type, token)
  elif bsm_type == 'BSM_TOKEN_TRAILER':
    return u'[{}: {}]'.format(bsm_type, token.record_length)
  elif bsm_type == 'BSM_TOKEN_FILE':
    timestamp = token.timestamp
    # TODO: Add microsecond...
    # token.microsecond
    human_timestamp = datetime.datetime.fromtimestamp(
        timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return u'[{0}: {1}, timestamp: {2}]'.format(
        bsm_type, _RawToUTF8(token.file_name), human_timestamp)
  elif bsm_type == 'BSM_TOKEN_IPC':
    return u'[{}: object type {}, object id {}]'.format(
        bsm_type, token.object_type, token.object_id)
  elif (bsm_type == 'BSM_TOKEN_PROCESS32' or
      bsm_type == 'BSM_TOKEN_PROCESS64'):
    return (u'[{}: aid({}), euid({}), egid({}), uid({}), gid({}), '
            u'pid({}), session_id({}), terminal_port({}), '
            u'terminal_ip({})]'.format(
                bsm_type,
                token.subject_data.audit_uid,
                token.subject_data.effective_uid,
                token.subject_data.effective_gid,
                token.subject_data.real_uid,
                token.subject_data.real_gid,
                token.subject_data.pid,
                token.subject_data.session_id,
                token.terminal_port,
                _IPv4Format(token.ipv4)))
  elif (bsm_type == 'BSM_TOKEN_PROCESS32_EX' or
      bsm_type == 'BSM_TOKEN_PROCESS64_EX'):
    if token.bsm_ip_type_short.net_type == AU_IPv6:
      ip = _IPv6Format(
          token.bsm_ip_type_short.ip_addr.high,
          token.bsm_ip_type_short.ip_addr.low)
    elif token.bsm_ip_type_short.net_type == AU_IPv4:
      ip = _IPv4Format(token.bsm_ip_type_short.ip_addr)
    else:
      ip = 'unknown'
    return (u'[{}: aid({}), euid({}), egid({}), uid({}), gid({}), '
            u'pid({}), session_id({}), terminal_port({}), '
            u'terminal_ip({})]'.format(
                bsm_type,
                token.subject_data.audit_uid,
                token.subject_data.effective_uid,
                token.subject_data.effective_gid,
                token.subject_data.real_uid,
                token.subject_data.real_gid,
                token.subject_data.pid,
                token.subject_data.session_id,
                token.terminal_port, ip))
  elif bsm_type == 'BSM_TOKEN_DATA':
    data = []
    data_type = BSM_TOKEN_DATA_TYPE.get(token.data_type, '')
    if data_type == 'AUR_CHAR':
      for _ in range(token.unit_count):
        data.append(BSM_TOKEN_DATA_CHAR.parse_stream(f))
    elif data_type == 'AUR_SHORT':
      for _ in range(token.unit_count):
        data.append(BSM_TOKEN_DAT_SHORT.parse_stream(f))
    elif data_type == 'AUR_INT32':
      for _ in range(token.unit_count):
        data.append(BSM_TOKEN_DATA_INTEGER.parse_stream(f))
    else:
      data.append(u'Unknown type data')
    # TODO: the data when it is string ends with ".", HW a space is return
    #       after uses the UTF-8 conversion.
    return u'[{}: Format data: {}, Data: {}]'.format(
        bsm_type,
        BSM_TOKEN_DATA_PRINT[token.how_to_print],
        _RawToUTF8(u''.join(data)))
  elif (bsm_type == 'BSM_TOKEN_ATTR32' or
      bsm_type == 'BSM_TOKEN_ATTR64'):
    return (u'[{0}: Mode: {1}, UID: {2}, GID: {3}, '
            u'File system ID: {4}, Node ID: {5}, Device: {6}]'.format(
                bsm_type, token.file_mode, token.uid, token.gid,
                token.file_system_id, token.file_system_node_id,
                token.device))
  elif bsm_type == 'BSM_TOKEN_GROUPS':
    arguments = []
    for _ in range(token):
      arguments.append(
          _RawToUTF8(BSM_TOKEN_DATA_INTEGER.parse_stream(
              f)))
    return u'[{}: {}]'.format(bsm_type, u','.join(arguments))
  elif bsm_type == 'BSM_TOKEN_AUT_SOCKINET32_EX':
    if BSM_PROTOCOLS.get(token.socket_domain, '') == 'INET6':
      sadd = _Ipv6Format(
          token.structure_addr_port.saddr_high,
          token.structure_addr_port.saddr_low)
      dadd = _Ipv6Format(
          token.structure_addr_port.daddr_high,
          token.structure_addr_port.daddr_low)
      return u'[{}: from {} port {} to {} port {}]'.format(
          bsm_type, sadd, token.structure_addr_port.source_port,
          dadd, token.structure_addr_port.destination_port)
    else:
      return u'[{}: from {} port {} to {} port {}]'.format(
          bsm_type,
          _IPv4Format(token.structure_addr_port.source_address),
          token.structure_addr_port.source_port,
          _IPv4Format(token.structure_addr_port.destination_address),
          token.structure_addr_port.destination_port)
  elif bsm_type == 'BSM_TOKEN_OPAQUE':
    return u'[{}: {}]'.format(bsm_type, token.encode('hex'))
  elif bsm_type == 'BSM_TOKEN_SEQUENCE':
    return u'[{}: {}]'.format(bsm_type, token)

# Provide a readable IPv6 IP having the high and low part in 2 integers.
# Args:
# high: 64 bits integers number with the high part of the IPv6.
# low: 64 bits integers number with the low part of the IPv6.
# Returns: string with a well represented IPv6.
def _IPv6Format(high, low):
  ipv6_string = IPV6_STRUCT.build(
      construct.Container(high=high, low=low))
  return socket.inet_ntop(
      socket.AF_INET6, ipv6_string)

# Change an integer IPv4 address value for its 4 octets representation.
# Args:
#   address: integer with the IPv4 address.
# Returns: IPv4 address in 4 octect representation (class A, B, C, D).
def _IPv4Format(address):
  ipv4_string = IPV4_STRUCT.build(address)
  return socket.inet_ntoa(ipv4_string)

# Pyparsing reads in RAW, but the text must be in UTF8.
def _RawToUTF8(text):
  try:
    text = text.decode('utf-8')
  except UnicodeDecodeError:
    logging.warning(
        u'Decode UTF8 failed, the message string may be cut short.')
    text = text.decode('utf-8', 'ignore')
  return text.partition('\x00')[0]

# Read one BSM Event
# Args:
#   f : BSM file.
#   token_id: header token_id.
#   event_number: the number of the event.
def ReadBSMEvent(f, token_id, event_number):
  first_byte = f.tell() - 1
  bsm_type, structure = BSM_TYPE_LIST.get(token_id, ['', ''])
  if bsm_type == 'BSM_HEADER32':
      token = structure.parse_stream(f)
  elif bsm_type == 'BSM_HEADER64':
    token = structure.parse_stream(f)
  elif bsm_type == 'BSM_HEADER32_EX':
    token = structure.parse_stream(f)
  else:
    print "[Error] At 0x{:X} header unknown.".format(f.tell())
    exit(1)

  data = []
  length = token.bsm_header.length
  next_entry = first_byte + length
  event_type = u'{0} ({1})'.format(
      BSM_AUDIT_EVENT.get(token.bsm_header.event_type, 'UNKNOWN'),
      token.bsm_header.event_type)
  human_timestamp = datetime.datetime.fromtimestamp(
        token.timestamp).strftime('%Y-%m-%d %H:%M:%S')

  # Read until we reach the end of the record.
  while f.tell() < (first_byte + length):
    # Check if it is a known token.
    try:
      token_id = BSM_TYPE.parse_stream(f)
    except (IOError, construct.FieldError):
      print (
          u'Unable to parse the Token ID at '
          u'position "{}"'.format(f.tell()))
      return
    # Unknown token id
    if not token_id in BSM_TYPE_LIST:
      f.seek(next_entry - f.tell(), os.SEEK_CUR)
      print '\t[Unfinished] Event: {}.\n\tType: {}.\n\tTimestamp: {}.'.format(
          event_number, event_type, human_timestamp)
      for i in range(len(data)):
        print u'\t{}'.format(data[i])
      print ''
      return
    else:
      token = BSM_TYPE_LIST[token_id][1].parse_stream(f)
      data.append(FormatToken(token_id, token, f))

    if f.tell() > next_entry:
      logging.warning(
          u'Token ID {0} not expected at position 0x{1:X}.'
          u'Jumping to the next entry'.format(
              token_id, f.tell()))
      f.seek(next_entry - f.tell(), os.SEEK_CUR)
      return
  print '\tEvent: {}.\n\tType: {}.\n\tTimestamp: {}.'.format(
      event_number, event_type, human_timestamp)
  for i in range(len(data)):
    print u'\t{}'.format(data[i])
  print ''

# Check if the file is a BSM file.
#
# Args:
#   f : file that we want to check.
def VerifyFile(f):
  type = BSM_TYPE.parse_stream(f)
  if (BSM_TYPE_LIST[type][0] != 'BSM_HEADER32' and
      BSM_TYPE_LIST[type][0] != 'BSM_HEADER64' and
      BSM_TYPE_LIST[type][0] != 'BSM_HEADER32_ex'):
    print '[Error] It is not a BSM file, unknown header token_id.'
    exit(1) 
  try: 
    header = BSM_HEADER.parse_stream(f)
  except:
    print '[Error] It is not a BSM file, not a header structure.'
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
  event_number = 0
  token_id = BSM_TYPE.parse_stream(f)
  while token_id:
    event_number += 1
    ReadBSMEvent(f, token_id, event_number)
    try:
      token_id = BSM_TYPE.parse_stream(f)
    except:
      token_id = None
  f.close() 
    

__init__()

