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

function usage()
{
  echo("\nBGP Policy Generator v".VERSION." (Oct 11 2017)\n\n");
  echo("Usage: ".basename(realpath(__FILE__))." [OPTIONS] <platform> <config_type> [template_id1[,template_id2,...]]\n\n");
  echo(" --help|-h                      This help message\n");
  echo(" --before|-b <date>             Generate first configuration before this date\n");
  echo(" --after|-a <date>              Generate first configuration after this date\n");
  echo(" --mail|-m [email_addresses]    Send generated configuration via email\n");
  echo(" --replyto|-r [email_addresses] Set Reply-To for generated configuration email\n");
  echo(" --file|-f <output_filename>    Write generated configuration to file\n\n");
  exit(255);
}

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

// Unless debug is set to full ...
if(!isset($config['debug']) ||
   !($config['debug'] & 'php'))
  // ... suppress PHP messages
  error_reporting(~E_ALL);

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
    case '-m':
    case '--mail':
      // If no email is given as argument ...
      if(empty($argv[0]) || !preg_match('/@/', $argv[0]))
        // ... use notify email from configuration
        $email = $config['notify_email'];
      // Otherwise ...
      else
        // ... use argument as email
        $email = array_shift($argv);
      // Supress output to stdout
      $suppress = true;
      break;
    case '-r':
    case '--replyto':
      // If no email is given as argument ...
      if(empty($argv[0]) || !preg_match('/@/', $argv[0]))
        // ... use reply-to email from configuration
        $reply_to = $config['reply_to_email'];
      // Otherwise ...
      else
        // ... use argument as reply-to email
        $reply_to = array_shift($argv);
      break;
    case '-f':
    case '--file':
      // Get destination filename
      $filename = array_shift($argv);
      // Filename is missing ?
      if(empty($filename))
        usage();
      // Supress output to stdout
      else
        $suppress = true;
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
$formatted_conf = generate_configs($platform, $type, $id, $time);
if(empty($formatted_conf))
  exit(255);

list($conf_text, $content_type) = $formatted_conf;
if(empty($conf_text) || empty($content_type))
  exit(255);

// If file name is defined ...
if(!empty($filename)) {
  // ... save generated config to file
  if(file_put_contents($filename, $conf_text) === FALSE) {
    echo("Failed to write generated configuration to file ".$filename."\n");
    exit(255);
  }
  echo("Successfully written generated configuration to file ".$filename."\n");
}

// If target email address is defined ...
if(!empty($email)) {
  // One or more recipients
  $recipients = is_array($email) ?
                  implode(",", $email):
                  $email;
  // Do we have a valid From address ?
  if(!empty($config['my_email'])) {
    if(!empty($config['my_name']))
      $headers = "From: ".$config['my_name']." <".$config['my_email'].">\r\n";
    else
      $headers = "From: ".$config['my_email']."\r\n";
  }
  // Do we have Reply-To address(es) defined ?
  if(!empty($reply_to))
    $headers .= "Reply-To: ".(is_array($reply_to) ? implode(",", $reply_to):$reply_to)."\r\n";
  // Format Subject field
  $subject = "[BGP Policy Generator] ".$platform." ".$type." ".$id;
  // Send generated configuration via email
  if(mail($recipients, $subject, $conf_text, $headers) === FALSE) {
    echo("Failed to send generated configuration to ".$recipients."\n");
    exit(255);
  }
  echo("Successfully sent generated configuration to ".$recipients."\n");
}

// Dump generated config to stdout by default
if(empty($suppress))
  echo($conf_text);

exit(0);

?>
