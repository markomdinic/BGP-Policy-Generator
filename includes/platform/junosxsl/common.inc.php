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

function junosxsl_content_type()
{
  return "text/xml";
}

function junosxsl_begin(&$junos_conf)
{
  global $config, $junosxsl_wrapper;

  // Load XSLT JunOS operation script to
  // wrap around our generated policy
  $script = file_get_contents($config['includes_dir'].'/platform/junosxsl/script.xsl');
  if(empty($script))
    return false;
  // Split script into individual lines
  $junosxsl_wrapper = explode("\n", $script);
  // Copy 'header' part (up to the placeholder)
  while(count($junosxsl_wrapper)) {
    $line = array_shift($junosxsl_wrapper);
    if(empty($line))
      continue;
    if(preg_match('/#{5}\sPOLICY\sPLACEHOLDER\s#{6}\sDO\sNOT\sCHANGE\s#{5}/', $line))
      break;
    $junos_conf[] = $line;
  }
}

function junosxsl_end(&$junos_conf)
{
  global $junosxsl_wrapper;

  // If wrapper was loaded ...
  if(empty($junosxsl_wrapper))
    return;
  // Copy the 'footer' part of the wrapper
  foreach($junosxsl_wrapper as $line)
    $junos_conf[] = $line;
}

?>
