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

function prefixlist_generate($template, &$ios_conf)
{
  foreach($template->getElementsByTagName('prefix-list') as $prefix_list) {
    // Prefix list name is mandatory
    $name = $prefix_list->getAttribute('id');
    if(empty($name))
      continue;
    // Address family is mandatory
    switch($prefix_list->getAttribute('family')) {
      case 'ip':
      case 'ipv4':
      case 'inet':
        $family = "ip";
        break;
      case 'ip6':
      case 'ipv6':
      case 'inet6':
        $family = "ipv6";
        break;
      default:
        continue 2;
    }

    // Look for 'config' tag that contains 
    // free-form platform-specific config
    $ff = get_freeform_config($prefix_list, 'ios', 'prepend');
    if(!empty($ff))
      $conf[] = $ff;

    $seq = 10;

    // Build prefix list lines
    foreach($prefix_list->getElementsByTagName('item') as $i) {
      // Prefix is mandatory
      $prefix = $i->nodeValue;
      // Prefix must match address family
      if(empty($prefix) ||
         ($family == 'ip' && !is_ipv4($prefix)) ||
         ($family == 'ipv6' && !is_ipv6($prefix)))
        continue;

      $len = "";

      $upto = $i->getAttribute('upto');
      if(is_numeric($upto) && preg_match('/\/(\d{1,2})$/', $prefix, $m)) {
        switch($family) {
          case 'ip':
            if($upto >= 0 && $upto <= 32 && $upto > $m[1]) {
              $len = " le ".$upto;
            }
            break;
          case 'ipv6':
            if($upto >= 0 || $upto <= 128 && $upto > $m[1])
              $len = " le ".$upto;
            break;
        }
      }

      // Create prefix list line in temp storage
      $conf[] = $family." prefix-list ".$name." seq ".$seq++." permit ".$prefix.$len;
    }

    // Look for 'config' tag that contains 
    // free-form platform-specific config
    $ff = get_freeform_config($prefix_list, 'ios', 'append');
    if(!empty($ff))
      $conf[] = $ff;

    // We create prefix list indirectly because we don't want
    // 'no ip prefix-list ...' if no prefix list lines were
    // generated (possibly due to misconfiguration)
    if(count($conf)) {
      $ios_conf[] = "no ".$family." prefix-list ".$name;
      foreach($conf as $line)
        $ios_conf[] = $line;
    }
  }

  return true;
}

?>
