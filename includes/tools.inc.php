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

function is_asn($asn)
{
  if(preg_match('/^(?:AS)?(\d+)$/i', $asn, $m))
    if($m[1] >= 1 && $m[1] <= 4294967294)
      return true;

  return false;
}

function is_ipv4($prefix)
{
  if(preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $prefix))
    return true;

  return false;
}

function is_ipv6($prefix)
{
  if(preg_match('/^(?:((?=(?>.*?(::))(?!.*?\2)))\2?|([\da-f]{1,4}(?:\2|:\b|(?=[^\da-f]|\b))|\1))(?3){7}\/\d{1,2}$/i', $prefix))
    return true;

  return false;
}

?>
