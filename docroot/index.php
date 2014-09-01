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

// Supress error messages
error_reporting(~E_ALL);

// Bail out without parameters
if(empty($_GET) || empty($_GET['platform']) || empty($_GET['type']))
  exit(0);

// This will hold our own configuration
$config = array('base_dir' => dirname(realpath(__FILE__)).'/..');

// Load our own configuration
include $config['base_dir']."/config.php";
// Load common code library
include $config['includes_dir']."/functions.inc.php";

// Set the default time zone
date_default_timezone_set(empty($config['timezone']) ? 'UTC':$config['timezone']);

$platform = empty($_GET['platform']) ? '':$_GET['platform'];
$type = empty($_GET['type']) ? '':$_GET['type'];
$id = empty($_GET['id']) ? NULL:$_GET['id'];

if(!empty($_GET['before']))
  $time = '<'.strtotime($_GET['before']);
elseif(!empty($_GET['after']))
  $time = '>'.strtotime($_GET['after']);
else
  $time = NULL;

if($platform == 'template' && $type == 'update')
  // Update autopolicies
  update_templates($id);
else
  // Generate device configuration
  generate_configs($platform, $type, $id, $time);

?>
