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

function prefixlist_generate($template, &$junos_conf)
{
  foreach($template->getElementsByTagName('prefix-list') as $prefix_list) {
    // Prefix list name is mandatory
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
    $ff = get_freeform_config($prefix_list, 'junos', 'prepend');
    if(!empty($ff))
      $conf[] = $ff;

    // Build prefix list items
    foreach($prefix_list->getElementsByTagName('item') as $i) {
      // Prefix is mandatory
      $prefix = $i->nodeValue;
      // Prefix must match address family
      if(empty($prefix) ||
         ($family == 4 && !is_ipv4($prefix)) ||
         ($family == 6 && !is_ipv6($prefix)))
        continue;
      // Build prefix list items in temporary storage
      $conf[] = $prefix.";";
    }

    // Look for 'config' tag that contains
    // free-form, platform-specific config
    $ff = get_freeform_config($prefix_list, 'junos', 'append');
    if(!empty($ff))
      $conf[] = $ff;

    // We create prefix list indirectly to avoid adding
    // an empty prefix-list into configuration in case
    // no prefix list items were generated (possibly due
    // to misconfiguration).
    if(count($conf)) {
      $junos_conf[] = "prefix-list ".$name." {";
      foreach($conf as $line)
        $junos_conf[] = "    ".$line;
      $junos_conf[] = "}";
    }
  }

  return true;
}

?>
