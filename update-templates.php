#!/usr/bin/env php
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

if(count($argv) > 2) {
  echo("Usage: ".basename(realpath(__FILE__))." [autopolicy_name]\n");
  exit(255);
}

// This will hold our own configuration
$config = array('base_dir' => dirname(realpath(__FILE__)));

// Load our own configuration
include $config['base_dir']."/config.php";
// Load common code library
include $config['includes_dir']."/functions.inc.php";

if(!empty($argv[1]))
  // Update specific autopolicy from RIPE
  update_template_by_name($argv[1]);
else
  // Update all autopolicies from RIPE
  update_all_templates();

?>
