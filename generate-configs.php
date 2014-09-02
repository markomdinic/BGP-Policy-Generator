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

function usage()
{
  echo("Usage: ".basename(realpath(__FILE__))." [--help|-h] [--before|-b <date>] [--after|-a <date>] <platform> <config_type> [template_id1,template_id2,...]\n");
  exit(255);
}

// This will hold our own configuration
$config = array('base_dir' => dirname(realpath(__FILE__)));

// Load our own configuration
include $config['base_dir']."/config.php";
// Load common code library
include $config['includes_dir']."/functions.inc.php";

// Set the default time zone
date_default_timezone_set(empty($config['timezone']) ? 'UTC':$config['timezone']);

$time = NULL;

// Skip script name
array_shift($argv);
// Get optional parameters
while(count($argv) > 0) {
  $arg = array_shift($argv);
  if(empty($arg))
    break;
  switch($arg) {
    case '-h':
    case '--help':
      usage();
      break;
    case '-b':
    case '--before':
      // Time argument already defined
      if(!empty($time))
        usage();
      // Get time argument
      $arg = array_shift($argv);
      // Time argument is missing
      if(empty($arg))
        usage();
      // Format time parameter
      $time = '<'.strtotime($arg);
      break;
    case '-a':
    case '--after':
      // Time argument already defined
      if(!empty($time))
        usage();
      // Get time argument
      $arg = array_shift($argv);
      // Time argument is missing
      if(empty($arg))
        usage();
      // Format time parameter
      $time = '>'.strtotime($arg);
      break;
    default:
      $args[] = $arg;
      break;
  }
}

// No less than 2 and no more than 3 arguments
if(empty($args) || count($args) < 2 || count($args) > 3)
  usage();

$platform = empty($args[0]) ? NULL:$args[0];
$type = empty($args[1]) ? NULL:$args[1];
$id = empty($args[2]) ? NULL:$args[2];

// Generate device configuration
generate_configs($platform, $type, $id, $time);

?>
