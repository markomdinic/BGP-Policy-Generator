<?php

// Our autonomous system number
$config['local_as'] = "65535";
// Get prefixes from RIS, rather than Whois ?
$config['use_ris'] = false;

// Whois parameters
$config['whois_ris_server'] = "riswhois.ripe.net";
$config['whois_server'] = "whois.ripe.net";
$config['whois_port'] = 43;
$config['whois_timeout'] = 20;
$config['whois_delay'] = 5;

// Personality to use for commits
// and notification emails
$config['my_name'] = "BGP Policy Generator";
$config['my_email'] = "root@localhost";

// Notification parameters
$config['notify_email'] = "you@yourdomain.net";
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

// Directories
$config['includes_dir'] = $config['base_dir']."/includes";
$config['templates_dir'] = $config['base_dir']."/templates";

// External programs
$config['git'] = "/usr/bin/git";

?>
