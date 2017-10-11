<?php
/*

 Copyright (c) 2017 Marko Dinic. All rights reserved.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

// BGP Policy Generator's current version
define('RELEASE_VERSION', '0.1.1');
define('RELEASE_DATE',    'Oct 12 2017');

// Address families
if(!defined('AF_INET'))
  define('AF_INET',       2);

if(!defined('AF_INET6'))
  define('AF_INET6',      10);

// Errno
define('EAGAIN',          11);    // Try again
define('EWOULDBLOCK',     11);    // Operation would block
define('ENOTSOCK',        88);    // Socket operation on non-socket
define('EDESTADDRREQ',    89);    // Destination address required
define('EMSGSIZE',        90);    // Message too long
define('EPROTOTYPE',      91);    // Protocol wrong type for socket
define('ENOPROTOOPT',     92);    // Protocol not available
define('EPROTONOSUPPORT', 93);    // Protocol not supported
define('ESOCKTNOSUPPORT', 94);    // Socket type not supported
define('EOPNOTSUPP',      95);    // Operation not supported on transport endpoint
define('EPFNOSUPPORT',    96);    // Protocol family not supported
define('EAFNOSUPPORT',    97);    // Address family not supported by protocol
define('EADDRINUSE',      98);    // Address already in use
define('EADDRNOTAVAIL',   99);    // Cannot assign requested address
define('ENETDOWN',        100);   // Network is down
define('ENETUNREACH',     101);   // Network is unreachable
define('ENETRESET',       102);   // Network dropped connection because of reset
define('ECONNABORTED',    103);   // Software caused connection abort
define('ECONNRESET',      104);   // Connection reset by peer
define('ENOBUFS',         105);   // No buffer space available
define('EISCONN',         106);   // Transport endpoint is already connected
define('ENOTCONN',        107);   // Transport endpoint is not connected
define('ESHUTDOWN',       108);   // Cannot send after transport endpoint shutdown
define('ETOOMANYREFS',    109);   // Too many references: cannot splice
define('ETIMEDOUT',       110);   // Connection timed out
define('ECONNREFUSED',    111);   // Connection refused
define('EHOSTDOWN',       112);   // Host is down
define('EHOSTUNREACH',    113);   // No route to host
define('EALREADY',        114);   // Operation already in progress
define('EINPROGRESS',     115);   // Operation now in progress
define('EREMOTEIO',       121);   // Remote I/O error
define('ECANCELED',       125);   // Operation Canceled

// RPSL object types
// (by object name)
define('RPSL_AS',         0x00000001);     // AS number
define('RPSL_PREFIX',     0x00000002);     // IPv4/IPv6 prefix
define('RPSL_OBJECTS',    0x80000000);     // Return full objects instead of primary keys

// Debug message categories
define('info',            0x00000001);
define('transport',       0x00000002);
define('raw',             0x00000004);
define('parser',          0x00000008);
define('cache',           0x00000010);
define('preprocessor',    0x00000020);
define('rpsl',            0x00000040);
define('expression',      0x00000080);
define('as-path',         0x00000100);
define('php',             0x80000000);
define('all',             0xffffffff);
define('full',            0xffffffff);

?>
