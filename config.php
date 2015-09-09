<?php

// Our autonomous system number
$config['local_as']       = "65535";

// First server to be queried
$config['whois'][] = array(
  'server'                => "whois.ripe.net",
  'port'                  => 43,
  'type'                  => "ripe",
//  'family'                => "inet6,inet",
//  'source'                => "ripe",
//  'sock_timeout'          => 5,
//  'query_timeout'         => 1800,
//  'query_size'            => 1000
);
// Second server to be queried
$config['whois'][] = array(
  'server'                => "whois.radb.net",
  'port'                  => 43,
  'type'                  => "irrd",
//  'family'                => "inet",
//  'source'                => "ripe,arin,radb",
//  'sock_timeout'          => 5,
//  'query_timeout'         => 1800,
//  'query_size'            => 1000
);

// Personality to use for commits
// and notification emails
$config['my_name']        = "BGP Policy Generator";
$config['my_email']       = "root@localhost";

// Notification parameters
$config['notify_changes'] = false;                      // Send notification ?
$config['notify_files']   = true;                       // Include the list of changed files ?
$config['notify_detail']  = true;                       // Include the changes diff ?
$config['notify_email']   = "you@yourdomain.net";       // Notification recipient(s)
$config['reply_to_email'] = "yourteam@yourdomain.net";  // Optional Reply-To address(es)

// Scripts to execute on autopolicy change
$config['on_change']      = array();

// Owner of templates dir
$config['user']           = "httpd";
$config['group']          = "httpd";

// Default time zone
$config['timezone']       = "UTC";

// External programs
$config['git']            = "/usr/bin/git";

// Debug messages
$config['debug']          = false;

?>
