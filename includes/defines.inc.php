<?php
/*

 Copyright (c) 2014 Marko Dinic <marko@yu.net>. All rights reserved.

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

if(!defined('AF_INET'))
  define('AF_INET',       2);

if(!defined('AF_INET6'))
  define('AF_INET6',      10);

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

?>
