#!/usr/bin/env php
<?php
/*

 Copyright (c) 2017 Marko Dinic <marko@yu.net>. All rights reserved.

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

// Set memory limit high to avoid
// errors with large data sets
ini_set('memory_limit', '3072M');

// This will hold our own configuration
$base_dir = dirname(realpath(__FILE__));
$config = array(
  'base_dir' => $base_dir,
  'includes_dir' => $base_dir."/includes",
  'templates_dir' => $base_dir."/templates"
);

// Load our own defines
include $config['includes_dir']."/defines.inc.php";
// Load our own configuration
include $config['base_dir']."/config.php";
// Load common code library
include $config['includes_dir']."/functions.inc.php";

// If no script is defined, do nothing
if(empty($config['on_change']))
  exit(0);

// Unless debug is set to full ...
if(!isset($config['debug']) ||
   !($config['debug'] & 'php'))
  // ... suppress PHP messages
  error_reporting(~E_ALL);

print $config['on_change']."\n";
// Get changed files
$changed = vcs_changed_files();
$args = empty($changed) ? '':' '.implode(' ', $changed);

// Make sure we are iterating over an array
$on_change = is_array($config['on_change']) ?
                $config['on_change']:array($config['on_change']);

// Execute each script in order
// in which they were defined
foreach($on_change as $script) {
  // If path points to an executable ...
  if(is_executable($script))
    // ... invoke it
    exec($script.$args);
}

?>
