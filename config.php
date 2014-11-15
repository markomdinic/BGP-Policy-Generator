<?php

// Our autonomous system number
$config['local_as'] = "65535";

// Whois parameters
$config['whois_server'] = "whois.ripe.net";
$config['whois_port'] = 43;
$config['whois_type'] = "ripe";
$config['whois_source'] = "ripe";
$config['whois_sock_timeout'] = 5;
$config['whois_query_timeout'] = 300;

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

?>
