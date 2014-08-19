<?php

// Directories
$config['includes_dir'] = $config['base_dir']."/includes";
$config['templates_dir'] = $config['base_dir']."/templates";

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

?>
