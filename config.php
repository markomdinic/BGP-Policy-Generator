<?php

// Our autonomous system number
$config['local_as'] = "65535";

// First server to be queried
$config['whois'][] = array(
  'server'         => "whois.ripe.net",
  'port'           => 43,
  'family'         => "inet6,inet",
  'type'           => "ripe",
  'source'         => "ripe",
  'sock_timeout'   => 5,
  'query_timeout'  => 300,
  'query_size'     => 100
);
// Second server to be queried
$config['whois'][] = array(
  'server'         => "whois.radb.net",
  'port'           => 43,
  'family'         => "inet",
  'type'           => "irrd",
  'source'         => "ripe,arin,apnic,afrinic,radb",
  'sock_timeout'   => 5,
  'query_timeout'  => 300,
  'query_size'     => 50
);

// Personality to use for commits
// and notification emails
$config['my_name'] = "BGP Policy Generator";
$config['my_email'] = "root@localhost";

// Notification parameters
$config['notify_email'] = "you@yourdomain.net";
$config['reply_to_email'] = "yourteam@yourdomain.net";
$config['notify_changes'] = false;  // Send notification ?
$config['notify_files'] = true;     // Include changed files ?
$config['notify_detail'] = true;    // Include changes diff ?

// Scripts to execute on autopolicy change
$config['on_change'] = array();

// Owner of templates dir
$config['user'] = "httpd";
$config['group'] = "httpd";

// Default time zone
$config['timezone'] = "UTC";

// External programs
$config['git'] = "/usr/bin/git";

// Debug messages
//  false  - disabled
//  true   - enabled
//  'full' - enabled + PHP warnings and errors
$config['debug'] = false;

?>
