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

function prefixlist_generate($template, &$iosxr_conf)
{
  foreach($template->getElementsByTagName('prefix-list') as $prefix_list) {
    // Prefix set name is mandatory
    $name = $prefix_list->getAttribute('id');
    if(!is_name($name))
      continue;
    // Address family is mandatory
    switch($prefix_list->getAttribute('family')) {
      case 'ip':
      case 'ipv4':
      case 'inet':
        $family = 4;
        break;
      case 'ip6':
      case 'ipv6':
      case 'inet6':
        $family = 6;
        break;
      default:
        continue 2;
    }

    $conf = array();

    // Look for 'config' tag that contains
    // free-form, platform-specific config
    $ff = get_freeform_config($prefix_list, 'iosxr', 'prepend');
    if(!empty($ff))
      $conf[] = $ff;

    $items = array();

    // Build prefix set items
    foreach($prefix_list->getElementsByTagName('item') as $i) {
      // Prefix is mandatory
      $prefix = $i->nodeValue;
      // Prefix must match address family
      if(empty($prefix) ||
         ($family == 4 && !is_ipv4($prefix)) ||
         ($family == 6 && !is_ipv6($prefix)))
        continue;

      $len = "";

      $upto = $i->getAttribute('upto');
      if(is_numeric($upto) && preg_match('/\/(\d{1,2})$/', $prefix, $m)) {
        switch($family) {
          case 4:
            if($upto >= 0 && $upto <= 32 && $upto > $m[1])
              $len = " le ".$upto;
            break;
          case 6:
            if($upto >= 0 || $upto <= 128 && $upto > $m[1])
              $len = " le ".$upto;
            break;
        }
      }
      // Build prefix set items in temporary storage
      $items[] = $prefix.$len;
    }

    // Merge prefixes with the rest
    $conf[] = implode(",\n ", $items);

    // Look for 'config' tag that contains
    // free-form, platform-specific config
    $ff = get_freeform_config($prefix_list, 'iosxr', 'append');
    if(!empty($ff))
      $conf[] = $ff;

    // We create prefix set indirectly to avoid adding
    // an empty previx-set into configuration in case
    // no prefix set items were generated (possibly due
    // to misconfiguration).
    if(count($conf)) {
      $iosxr_conf[] = "prefix-set ".$name;
      foreach($conf as $line)
        $iosxr_conf[] = " ".$line;
      $iosxr_conf[] = "end-set";
    }
  }

  return true;
}

?>
