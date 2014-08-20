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

include_once $config['includes_dir'].'/platform/junosxsl/common.inc.php';

function prefixlist_content_type()
{
  return junosxsl_content_type();
}

function prefixlist_begin(&$junos_conf)
{
  return junosxsl_begin($junos_conf);
}

function prefixlist_generate($template, &$junos_conf)
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

    // Look for 'config' tag that contains
    // free-form, platform-specific config
    $ff = get_freeform_config($prefix_list, 'junosxsl', 'prepend');
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
      $conf[] = "<prefix-list-item replace=\"replace\">";
      $conf[] = "<name>".$prefix."</name>";
      $conf[] = "</prefix-list-item>";
    }

    // Look for 'config' tag that contains
    // free-form, platform-specific config
    $ff = get_freeform_config($prefix_list, 'junosxsl', 'append');
    if(!empty($ff))
      $conf[] = $ff;

    // We create prefix list indirectly to avoid inserting
    // and empty <prefix-list> tag into configuration in
    // case no prefix list items were generated (possibly
    // due to misconfiguration).
    if(count($conf)) {
      $junos_conf[] = "<prefix-list>";
      $junos_conf[] = "<name>".$name."</name>";
      foreach($conf as $line)
        $junos_conf[] = $line;
      $junos_conf[] = "</prefix-list>";
    }
  }

  return true;
}

function prefixlist_end(&$junos_conf)
{
  return junosxsl_end($junos_conf);
}

?>
