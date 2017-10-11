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

function junosxsl_format(&$junos_conf)
{
  // Serialize generated configuration
  $conf_text = implode("\n", $junos_conf);
  // Create empty DOM hierarchy
  $doc = new DomDocument;
  $doc->preserveWhiteSpace = false;
  $doc->validateOnParse = true;
  // Load generated XML into DOM
  $doc->loadXML($conf_text);
  // Make it pretty
  $doc->formatOutput = true;
  // Put it back nicely formatted
  $conf_text = $doc->saveXML();

  return array($conf_text, "text/xml");
}

function junosxsl_begin(&$junos_conf)
{
  global $config, $junosxsl_wrapper;

  // Load XSLT JunOS operation script to
  // wrap around our generated policy
  $script = file_get_contents($config['includes_dir'].'/platform/junosxsl/script.xsl');
  if(empty($script))
    return false;
  // Split script into header and footer part. Placeholder line
  // should appear only once in the script and split it in 2 parts.
  // If it appears more than once, only the first and the last part
  // are used as header and footer, respectively, while the middle
  // is ignored, as it should not have existed in the first place.
  $junosxsl_wrapper = explode("<!-- ##### POLICY PLACEHOLDER ###### DO NOT CHANGE ##### -->", $script);
  // Copy the 'header' part of the wrapper
  $line = array_shift($junosxsl_wrapper);
  if(empty($line))
    continue;
  $junos_conf[] = $line;
}

function junosxsl_end(&$junos_conf)
{
  global $junosxsl_wrapper;

  // If wrapper was loaded ...
  if(empty($junosxsl_wrapper))
    return;
  // Copy the 'footer' part of the wrapper
  $line = array_pop($junosxsl_wrapper);
  if(empty($line))
    continue;
  $junos_conf[] = $line;
}

?>
