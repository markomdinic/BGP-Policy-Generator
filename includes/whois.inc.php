<?php
/*

 Copyright (c) 2015 Marko Dinic <marko@yu.net>. All rights reserved.

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

include_once $config['includes_dir'].'/tools.inc.php';

// ************************ LOW LEVEL WHOIS FUNCTIONS *************************

function whois_execute($server, $search, $options='')
{
  // Don't waste my time ...
  if(empty($search) || empty($server) || !is_array($server))
    return false;

  // Whois server host
  // (default: none)
  $host = $server['server'];
  if(empty($host))
    return false;

  $host = strtolower($host);

  // Whois server TCP port
  // (default: 43)
  $port = (!empty($server['port'])) ?
              $server['port']:43;

  // Address families for connection ('inet', 'inet6')
  // (default: 'inet6,inet')
  foreach(explode(',', (!empty($server['family'])) ? $server['family']:'inet6,inet') as $af) {
    switch(strtolower(trim($af))) {
      case 'inet':
        $address_families[] = AF_INET;
        break;
      case 'inet6':
        $address_families[] = AF_INET6;
        break;
      default:
        debug_message("Invalid address family \"".trim($af)."\". Check your configuration ?");
        return false;
    }
  }

  // Whois server type ('irrd', 'ripe')
  // (default: 'ripe')
  $type = (!empty($server['type'])) ?
              $server['type']:"ripe";

  // Socket operations (connect/read/write) timeout
  // (default: 5 seconds)
  $socket_timeout = (!empty($server['sock_timeout'])) ?
                        $server['sock_timeout']:5;

  // Query timeout (max time single query can last)
  // (default: 300 seconds)
  $query_timeout = (!empty($server['query_timeout'])) ?
                       $server['query_timeout']:300;

  // Query size (number of objects per query)
  // (default: 50)
  $query_size = (!empty($server['query_size'])) ?
                       $server['query_size']:50;

  // List of whois server addresses should persist
  // between calls in order to act as a DNS cache
  static $addrs;

  // If 'DNS cache' is empty ...
  if(empty($addrs))
    // ... create a new, empty one
    $addrs = array();

  // If host isn't cached ...
  if(!isset($addrs[$host]) || empty($addrs[$host])) {
    // Create a new cache entry
    $addrs[$host] = array();
    // Whois server specified as IPv4 address ?
    if(is_ipv4($host)) {
      $addrs[$host][AF_INET] = $host;
    // Whois server specified as IPv6 address ?
    } elseif(is_ipv6($host)) {
      $addrs[$host][AF_INET6] = $host;
    // Whois server specified as hostname ...
    } else {
      // Resolve whois server's hostname
      $records = dns_get_record($host, DNS_AAAA + DNS_A);
      if(!empty($records)) {
        // Process retrieved DNS records
        foreach($records as $record) {
          // Ignore empty records
          if(empty($record))
            continue;
          // Assign retrieved addresses
          // to their respective families
          switch($record['type']) {
            case 'A':
              $addrs[$host][AF_INET] = $record['ip'];
              break;
            case 'AAAA':
              $addrs[$host][AF_INET6] = $record['ipv6'];
              break;
          }
        }
      }
    }
    // Nothing to do if hostname failed to resolve
    if(empty($addrs[$host]))
      return false;
  }

  // Determine if and how to begin and end
  // persistent connection (bulk mode)
  switch($type) {
    // Whois server is 100% RIPE compatibile
    // (which is whois.ripe.net only, AFAIK)
    case 'ripe':
      $begin = "-k";
      $end = "-k";
      debug_message("Using RIPE-compatibile bulk query mode.");
      break;
    // Whois server is based on IRRd software.
    // It's compatibile with RIPE for the most
    // part, but persistant connection mode is
    // handled slightly differently
    case 'irrd':
      $begin = "!!";
      $end = "q";
      debug_message("Using irrd-compatibile bulk query mode.");
      break;
    default:
      debug_message("Using normal query mode.");
      break;
  }

  // Prepared queries will be stored here
  // and then taken from this array and
  // executed in the same order in which
  // they were added
  $queries = array();

  // Make sure search is always an array
  // even if it contains a single element
  if(!is_array($search))
    $search = array($search);

  // If bulk mode is enabled multiple queries will be executed
  // over a single persistent connection, query_size objects
  // per query. Without bulk mode, each query references a single
  // object, opening and closing a connection every time
  for($prepared = 0, $step = (!empty($begin) && !empty($end)) ? $query_size:1, $num_obj = sizeof($search);
      $prepared < $num_obj;
      $prepared += $step)
    // If bulk mode is enabled, prepare a query of query_size
    // number of objects. Otherwise, prepare a single object.
    // In either case, each RPSL object will have whois server
    // options prepended to it's name
    $queries[] = $options." ".implode("\n".$options." ", array_slice($search, $prepared, $step))."\n";

  // This will hold the response to our search
  // either retrieved all at once, in bulk mode
  // or built by fetching and appending object
  // by object, in default mode
  $response = '';

  debug_message("Querying server ".$host." ...");

  // First, we need to connect
  $sock = false;

  // Run all queries
  foreach($queries as $query) {

    // Do we need to connect ?
    if($sock === FALSE) {

      // Try address families in specified order
      foreach($address_families as $af) {
        // Skip address families not supported
        // by this whois server
        if(!isset($addrs[$host][$af]))
          continue;
        // Determine connect method
        switch($af) {
          case AF_INET:
            // Establish TCP connection to whois server over IPv4
            $sock = stream_socket_client("tcp://".$addrs[$host][$af].":".$port, $errno, $errstr, $socket_timeout);
            if($sock !== FALSE)
              break 2;
            break;
          case AF_INET6:
            // Establish TCP connection to whois server over IPv6
            $sock = stream_socket_client("tcp://[".$addrs[$host][$af]."]:".$port, $errno, $errstr, $socket_timeout);
            if($sock !== FALSE)
              break 2;
            break;
          default:
            return false;
        }
      }

      // Connection failed for whatever reason ?
      if($sock === FALSE)
        // Abort !
        return false;

      // Make connection non blocking
      stream_set_blocking($sock, 0);

      // If bulk mode is enabled ...
      if(!empty($begin) && !empty($end)) {
        // ... begin persistent connection
        if(fwrite($sock, $begin."\n") === FALSE) {
          fclose($sock);
          return false;
        }
      }

    }

    // A single query cannot last
    // longer than query_timeout
    $query_deadline = time() + $query_timeout;

    $null = NULL;

    // Send query to whois server
    for($total_sent = 0, $sent = 0, $query_length = strlen($query);
        $total_sent < $query_length;
        $total_sent += $sent, $sent = 0) {
      // Query timeout ?
      if(time() > $query_deadline) {
        fclose($sock);
        return false;
      }
      // Make a list of sockets to monitor
      // for write readiness, containing
      // our one and only socket
      $write_socks = array($sock);
      // Wait for our socket to become ready to send query
      $num_ready = stream_select($$null, $write_socks, $null, 1);
      // Error ?
      if($num_ready === FALSE) {
        fclose($sock);
        return false;
      }
      // Socket ready for writing ...
      // (should be most of the time)
      if($num_ready > 0) {
        // Send in 4K blocks
        $sent = fwrite($sock, substr($query, $total_sent), 4096);
        // Error ?
        if($sent === FALSE) {
          fclose($sock);
          return false;
        }
      }
    }

    // Receive response from whois server
    while(!feof($sock)) {
      // Query timeout ?
      if(time() > $query_deadline) {
        fclose($sock);
        return false;
      }
      // Make a list of sockets to monitor
      // for read readiness, containing
      // our one and only socket
      $read_socks = array($sock);
      // Wait for our socket to become ready to be read
      $num_ready = stream_select($read_socks, $null, $null, 1);
      // Error ?
      if($num_ready === FALSE) {
        fclose($sock);
        return false;
      }
      // We got everything we could
      // if connection is idle
      if($num_ready == 0)
        break;
      // Get a line of response
      $line = fgets($sock);
      // Socket closed ?
      if($line === FALSE) {
        // In normal mode, server has closed
        // the connection after delivering
        // the response
        if(empty($begin) || empty($end))
          break;
        // In bulk mode this shouldn't happen
        // since we are supposed to explicitly
        // end the bulk mode ourselves, so,
        // treat it as error
        fclose($sock);
        return false;
      }
      // Append retrieved line to the response
      $response .= $line;
    }

    // This newline is extremely important
    // in order to separate raw RPSL objects
    $response .= "\n";

    // If bulk mode is NOT enabled ...
    if(empty($begin) || empty($end)) {
      // ... close used connection
      fclose($sock);
      // ... force a new connection
      $sock = false;
    }

  }

  // At this point, all queries have been executed

  // If bulk mode is enabled ...
  if(!empty($begin) && !empty($end))
    // ... end persistent connection
    fwrite($sock, $end."\n");

  // Close the connection
  if($sock !== FALSE)
    fclose($sock);

  // Return cumulative response
  return $response;
}

// **************************** QUERY FUNCTIONS *******************************

function whois_query_server($server, $search, $type=NULL, $attr=NULL)
{
  // If search string(s) are missing ...
  if(empty($search))
    // ... return an empty result
    return;

  // If Whois server parameters are missing,
  // explicitly return FALSE, to signal
  // that something went wrong
  if(empty($server) || !is_array($server))
    return false;

  //
  // Leave out contact information
  // to avoid RIPE's daily limit ban:
  //
  //   http://www.ripe.net/data-tools/db/faq/faq-db/why-did-you-receive-the-error-201-access-denied
  //
  $options = '-r';
  // Preferred whois source
  if(!empty($server['source'])) {
    $sources = array();
    // Break down this comma-separated list, in case
    // it contains whitespaces (usually around commas)
    foreach(explode(',', $server['source']) as $source)
      $sources[] = strtolower(trim($source));
    // Rebuild comma-separated list, without whitespaces
    $options .= ' -s'.implode(',', $sources);
  }
  // Preferred object type
  if(!empty($type))
    $options .= ' -T'.$type;
  // Inverse lookup by this attribute
  if(!empty($attr))
    $options .= ' -i'.$attr;

  // Query whois server
  $response = whois_execute($server, $search, $options);
  // If something went wrong or we got nothing ...
  if(empty($response))
    // ... abort and propagate the result
    return $response;

  // Parsed objects go here
  $objects = array();

  // Split whois response into individual lines
  // and then parse them into RPSL objects
  foreach(explode("\n", $response) as $line) {

    // Object ends on an empty line
    if(empty($line)) {
      // If object and it's primary key are defined ...
      if(!empty($key) && !empty($object)) {
        // If object already exists in the list ...
        if(isset($objects[$key])) {
          // ... and is already an array ...
          if(is_sequential_array($objects[$key]))
            // ... add it along with other objects
            // with the same primary/lookup key
            $objects[$key][] = $object;
          // Otherwise, convert list entry to array ...
          else
            // ... containing both existing and the new object
            $objects[$key] = array($objects[$key], $object);
        // If object isn't in the list ...
        } else
          // ... just add it
          $objects[$key] = $object;
      }
      // Reset per-object variables
      unset($object, $key, $attr, $value, $skip);
      continue;
    }

    // Some part of this processing loop determined
    // that current object should be skipped ...
    if(isset($skip) && $skip == TRUE)
      continue;

    // Skip comments
    if(preg_match('/^\s*%/', $line))
      continue;

    // Looking for "attribute: value" line
    if(preg_match('/^([^\s:]+):\s*(.*?)\s*$/i', $line, $m)) {
      switch($m[1]) {
        // Pick used attributes
        case 'aut-num':
        case 'import':
        case 'export':
        case 'mp-import':
        case 'mp-export':
        case 'as-set':
        case 'route-set':
        case 'route6-set':
        case 'members':
        case 'route':
        case 'route6':
        case 'origin':
          $attr = $m[1];
          $value = $m[2];
          break;
        // Skip unused attributes
        default:
          unset($attr);
          continue 2;
      }

      // If no object is currently in construction ...
      if(empty($object)) {
        // If specific attribute was requested,
        // but doesn't match the object type ...
        if(!empty($type) && $type != $attr) {
          // ... skip it
          $skip = true;
          continue;
        }
        // If all went well, start a new object
        // and remember object's primary key
        $object = array();
        $key = $value;
      }

      // Store RPSL object
      if(is_array($object)) {
        // If attribute already exists ...
        if(isset($object[$attr])) {
          // ... and is already an array ...
          if(is_array($object[$attr]))
            // ... add value along with others
            $object[$attr][] = $value;
          // Otherwise, convert it to array ...
          else
            // ... which will hold previous and current value
            $object[$attr] = array($object[$attr], $value);
        // If attribute doesn't exist, create it
        } else
          $object[$attr] = $value;
      }

    // Line is a continuation of previous line(s) ?
    } elseif(!empty($attr) && preg_match('/^\s*(.+)/i', $line, $m)) {

      // Match should be a part of multiline value
      $value = $m[1];
      // Store RPSL object
      if(!empty($object) && is_array($object)) {
        // If attribute is an array ...
        if(is_array($object[$attr])) {
          $last = count($object[$attr]) - 1;
          // ... append to the last stored value
          $object[$attr][$last] .= $value;
        // Otherwise, if attribute holds a single value ...
        } else
          // ... simply append to it
          $object[$attr] .= $value;
      }

    }

  }

  return $objects;
}

function whois_query($search, $type=NULL, $attr=NULL, &$servers=NULL)
{
  global $config;

  // If Whois servers' weren't given ...
  if(empty($servers))
    // ... use globally configured ones
    $servers = &$config['whois'];

  // If we still have no servers ...
  if(empty($servers) || !is_array($servers))
    // ... signal that something is wrong
    return false;

  // Try configured Whois servers one by one,
  // in order in which they were specified.
  // Server list is passed by reference,
  // which means the original list will be
  // modified by removing failed servers
  // in order to avoid querying them again
  for($i = 0; $i <= sizeof($servers); $i++) {
    // Attempt to query the preferred server
    $response = whois_query_server($servers[0], $search, $type, $attr);
    // If query failed ...
    if($response === false) {
      if(isset($servers[0]['server']) && !empty($servers[0]['server']))
        debug_message("Removing failed server ".$servers[0]['server']." from the list.");
      else
        debug_message("Removing invalid server from the list. Check your configuration ?");
      // ... remove failed server from the list
      array_shift($servers);
      // ... try the next server
      continue;
    }
    // Otherwise, we are done
    return $response;
  }

  // If we reached this point,
  // we have no usable servers
  return false;
}

// ************************** RPSL OBJECT FUNCTIONS ***************************

function aut_num($asn, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($asn))
    return;

  // Uppercase the ASN
  $asn = strtoupper($asn);

  // Fetch aut-num object(s)
  $res = whois_query($asn,
                     'aut-num',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$asn]) ||
     !is_array($res[$asn]))
    return;

  // If we retrieved a single RPSL object,
  // place it into array to make sure we always
  // iterate over array. If it's not an RPSL
  // object, it's already an array of objects
  $objects = is_rpsl_object($res[$asn]) ?
                array($res[$asn]):$res[$asn];

  // Since multiple sources can be specified,
  // more than one version of the same aut-num
  // can be retrieved in the same order sources
  // were specified.
  foreach($objects as $object) {

    // Begin constructing new aut-num object
    $aut_num = array();

/*
    // Copy import attribute(s)
    if(isset($object['import'])) {
      $imports = is_array($object['import']) ?
                    $object['import']:
                    array($object['import']);
      foreach($imports as $import) {
        // Extract ASN we are importing from
        if(preg_match('/from\s+([^\s:;#]+)/i', $import, $m))
          $from = strtoupper($m[1]);
        // Extract filter that defines what will be imported
        if(preg_match('/accept\s+(?:\{\s*([^\{\}]+?)\s*\}|([^\s:;#]+))/i', $import, $m)) {
          // Inline filter ?
          if(!empty($m[1]))
            // Split inline filter specification
            // into an array of prefixes
            $what = preg_split('/(?:\^\S*)?[^A-F\d\.:\/]+/i', $m[1]);
          // AS, AS-SET, AS-ANY or ANY ?
          elseif(!empty($m[2]))
            // Make sure this is always uppercase
            $what = strtoupper($m[2]);
        }
        // Store dumbed down version of import attribute
        if(!empty($what))
          $aut_num['import'][$from] = $what;
      }
    }
*/
    // Copy export attribute(s)
    if(isset($object['export'])) {
      $exports = is_array($object['export']) ?
                    $object['export']:
                    array($object['export']);
      foreach($exports as $export) {
        // Extract ASN we are exporting to
        if(preg_match('/to\s+([^\s:;#]+)/i', $export, $m))
          $to = strtoupper($m[1]);
        // Extract filter that defines what will be exported
        if(preg_match('/announce\s+(?:\{\s*([^\{\}]+?)\s*\}|([^\s:;#]+))/i', $export, $m)) {
          // Inline filter ?
          if(!empty($m[1]))
            // Split inline filter specification
            // into an array of prefixes
            $what = preg_split('/(?:\^\S*)?[^A-F\d\.:\/]+/i', $m[1]);
          // AS, AS-SET, AS-ANY or ANY ?
          elseif(!empty($m[2]))
            // Make sure this is always uppercase
            $what = strtoupper($m[2]);
        }
        // Store dumbed down version of export attribute
        if(!empty($what))
          $aut_num['export'][$to] = $what;
      }
    }
/*
    // Copy mp-import attribute(s)
    if(isset($object['mp-import'])) {
      $imports = is_array($object['mp-import']) ?
                    $object['mp-import']:
                    array($object['mp-import']);
      foreach($imports as $import) {
        // Extract ASN we are importing from
        if(preg_match('/from\s+([^\s:;#]+)/i', $import, $m))
          $from = strtoupper($m[1]);
        // Extract filter that defines what will be imported
        if(preg_match('/accept\s+(?:\{\s*([^\{\}]+?)\s*\}|([^\s:;#]+))/i', $import, $m)) {
          // Inline filter ?
          if(!empty($m[1]))
            // Split inline filter specification
            // into an array of prefixes
            $what = preg_split('/(?:\^\S*)?[^A-F\d\.:\/]+/i', $m[1]);
          // AS, AS-SET, AS-ANY or ANY ?
          elseif(!empty($m[2]))
            // Make sure this is always uppercase
            $what = strtoupper($m[2]);
        }
        // Store dumbed down version of import attribute
        if(!empty($what))
          $aut_num['mp-import'][$from] = $what;
      }
    }
*/
    // Copy mp-export attribute(s)
    if(isset($object['mp-export'])) {
      $exports = is_array($object['mp-export']) ?
                    $object['mp-export']:
                    array($object['mp-export']);
      foreach($exports as $export) {
        // Extract ASN we are exporting to
        if(preg_match('/to\s+([^\s:;#]+)/i', $export, $m))
          $to = strtoupper($m[1]);
        // Extract filter that defines what will be exported
        if(preg_match('/announce\s+(?:\{\s*([^\{\}]+?)\s*\}|([^\s:;#]+))/i', $export, $m)) {
          // Inline filter ?
          if(!empty($m[1]))
            // Split inline filter specification
            // into an array of prefixes
            $what = preg_split('/(?:\^\S*)?[^A-F\d\.:\/]+/i', $m[1]);
          // AS, AS-SET, AS-ANY or ANY ?
          elseif(!empty($m[2]))
            // Make sure this is always uppercase
            $what = strtoupper($m[2]);
        }
        // Store dumbed down version of export attribute
        if(!empty($what))
          $aut_num['mp-export'][$to] = $what;
      }
    }

    // Sources are specified in descending order
    // of significance, thus we will pick the first
    // version of this aut-num that defines the info
    // we require (export attributes)
    if(!empty($aut_num) && 
       (isset($aut_num['export']) ||
        isset($aut_num['mp-export']))) {
      // ... add the rest of attributes of interest
      $aut_num['aut-num'] = $asn;
      // ... and it's done
      return $aut_num;
    }
  }

  // If we got to this point, none of the found versions
  // of this aut-num object had enough information to be
  // of any use to us
  return;
}

function as_set($as_set_name, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($as_set_name))
    return;

  // We always use uppercase names
  $as_set_name = strtoupper($as_set_name);

  // This will hold all expanded member ASNs
  $as_set_members = array();

  // Add ourselves to the expansion list
  $expand_as_sets = array($as_set_name => true);
  // Set ourselves as already expanded
  $already_expanded = array($as_set_name => true);

  // Do the deep expansion of this AS set
  while(!empty($expand_as_sets)) {

    // Fetch AS sets
    $as_sets = whois_query(array_keys($expand_as_sets),
                           'as-set',
                           NULL,
                           $servers);
    if(empty($as_sets))
      break;

    // Begin with an empty list of AS sets to expand.
    // This list will be used in the next iteration.
    $expand_as_sets = array();

    // Collect all members from all found AS set objects
    foreach(array_values($as_sets) as $object) {

      // Most basic sanity check
      if(empty($object) || !is_array($object))
        continue;

      // If we retrieved a single RPSL object,
      // place it into array to make sure we always
      // iterate over array. If it's not an RPSL
      // object, it's already an array of objects
      $objects = is_rpsl_object($object) ?
                          array($object):$object;

      // Proper AS set object must have members attribute(s)
      $as_set = NULL;
      // Each entry in the array of as-sets represents
      // a single as-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same as-set from different sources,
      // returned in the order sources were specified
      foreach($objects as $object) {
        // Sources are specified in descending order
        // of significance, thus we will pick the first
        // version of this as-set that has all the info
        // we require (members attribute)
        if(is_array($object) && isset($object['members'])) {
          $as_set = $object;
          break;
        }
      }

      if(empty($as_set))
        continue;

      // The list of unique members of current AS set
      $members = is_array($as_set['members']) ?
                   $as_set['members']:array($as_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
        // Skip parsing errors
        if(empty($member))
          continue;
        // String might contain comma-separated members list
        foreach(preg_split('/[,;:]/', strtoupper($member)) as $member) {
          // Strip leading and trailing trash
          if(!preg_match('/([^\s#]+)/', $member, $m))
            continue;
          $member = $m[1];
          // If member is a simple AS, AS-ANY or ANY ...
          if(is_asn($member) || is_any($member)) {
            // ... just store it along with the rest
            $as_set_members[$member] = true;
          // Otherwise, member should be an AS set.
          // So, unless already expanded ...
          } elseif(!isset($already_expanded[$member])) {
            // ... add it to the expansion list
            $expand_as_sets[$member] = true;
            // ... set it as expanded to prevent loops
            $already_expanded[$member] = true;
          }
        }
      }
    }
  }

  // If our expanded AS set has no members ...
  if(empty($as_set_members))
    // ... return nothing
    return;

  // Return expanded as-set
  return array('as-set' => $as_set_name,
               'members' => array_keys($as_set_members));
}

function route_set($route_set_name, &$servers=NULL)
{
  // Don't waste time
  if(empty($route_set_name))
    return;

  // We always use uppercase names
  $route_set_name = strtoupper($route_set_name);

  // This will hold all expanded member prefixes
  $route_set_members = array();

  // Add ourselves to the expansion list
  $expand_route_sets = array($route_set_name => true);
  // Set ourselves as already expanded
  $already_expanded = array($route_set_name => true);

  // Do the deep expansion of this route set
  while(!empty($expand_route_sets)) {

    // Fetch route sets
    $route_sets = whois_query(array_keys($expand_route_sets),
                              'route-set',
                              NULL,
                              $servers);
    if(empty($route_sets))
      break;

    // Begin with an empty list of route sets to expand.
    // This list will be used in the next iteration.
    $expand_route_sets = array();

    // Collect all members from all found route set objects
    foreach(array_values($route_sets) as $object) {

      // Most basic sanity check
      if(empty($object) || !is_array($object))
        continue;

      // If we retrieved a single RPSL object,
      // place it into array to make sure we always
      // iterate over array. If it's not an RPSL
      // object, it's already an array of objects
      $objects = is_rpsl_object($object) ?
                          array($object):$object;

      // Proper route set object must have members attribute(s)
      $route_set = NULL;
      // Each entry in the array of route-sets represents
      // a single route-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same route-set from different sources,
      // returned in the order sources were specified
      foreach($objects as $object) {
        // Sources are specified in descending order
        // of significance, thus we will pick the first
        // version of this route-set that has all the info
        // we require (members attribute)
        if(is_array($object) && isset($object['members'])) {
          $route_set = $object;
          break;
        }
      }

      if(empty($route_set))
        continue;

      // The list of unique members of current route set
      $members = is_array($route_set['members']) ?
                       array_unique($route_set['members']):
                       array($route_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
        // Skip parsing errors
        if(empty($member))
          continue;
        // String might contain comma-separated members list
        foreach(preg_split('/(?:\^[^,\s]*)?\s*[,\s]\s*/', strtoupper($member)) as $member) {
          // Strip leading and trailing trash
          if(!preg_match('/([^\s#]+)/', $member, $m))
            continue;
          $member = $m[1];
          // If member is an IPv4 prefix ...
          if(is_ipv4($member)) {
            // ... just store it along with the rest
            $route_set_members[$member] = true;
          // If member is RS-ANY or ANY ...
          } elseif(is_any($member)) {
            // ... store 0.0.0.0/0
            $route_set_members['0.0.0.0/0'] = true;
          // Otherwise, member should be a route set.
          // So, unless already expanded ...
          } elseif(!isset($already_expanded[$member])) {
            // ... add it to the expansion list
            $expand_route_sets[$member] = true;
            // ... set it as expanded to prevent loops
            $already_expanded[$member] = true;
          }
        }
      }
    }
  }

  // If our expanded route set has no members ...
  if(empty($route_set_members))
    // ... return nothing
    return;

  // Return expanded route-set
  return array('route-set' => $route_set_name,
               'members' => array_keys($route_set_members));
}

function route6_set($route6_set_name, &$servers=NULL)
{
  // Don't waste time
  if(empty($route6_set_name))
    return;

  // We always use uppercase names
  $route6_set_name = strtoupper($route6_set_name);

  // This will hold all expanded member prefixes
  $route6_set_members = array();

  // Add ourselves to the expansion list
  $expand_route6_sets = array($route6_set_name => true);
  // Set ourselves as already expanded
  $already_expanded = array($route6_set_name => true);

  // Do the deep expansion of this route set
  while(!empty($expand_route6_sets)) {

    // Fetch route sets
    $route6_sets = whois_query(array_keys($expand_route6_sets),
                               'route-set',
                               NULL,
                               $servers);
    if(empty($route6_sets))
      break;

    // Begin with an empty list of route sets to expand.
    // This list will be used in the next iteration.
    $expand_route6_sets = array();

    // Collect all members from all found route set objects
    foreach(array_values($route6_sets) as $route6_set) {

      // Most basic sanity check
      if(empty($object) || !is_array($object))
        continue;

      // If we retrieved a single RPSL object,
      // place it into array to make sure we always
      // iterate over array. If it's not an RPSL
      // object, it's already an array of objects
      $objects = is_rpsl_object($object) ?
                          array($object):$object;

      // Proper route6 set object must have members attribute(s)
      $route6_set = NULL;
      // Each entry in the array of route6-sets represents
      // a single route6-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same route6-set from different sources,
      // returned in the order sources were specified
      foreach($objects as $object) {
        // Sources are specified in descending order
        // of significance, thus we will pick the first
        // version of this route6-set that has all the info
        // we require (members attribute)
        if(is_array($object) && isset($object['members'])) {
          $route6_set = $object;
          break;
        }
      }

      if(empty($route6_set))
        continue;

      // The list of unique members of current route set
      $members = is_array($route6_set['members']) ?
                       array_unique($route6_set['members']):
                       array($route6_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
        // Skip parsing errors
        if(empty($member))
          continue;
        // String might contain comma-separated members list
        foreach(preg_split('/(?:\^[^,\s]*)?\s*[,\s]\s*/', strtoupper($member)) as $member) {
          // Strip leading and trailing trash
          if(!preg_match('/([^\s#]+)/', $member, $m))
            continue;
          $member = $m[1];
          // If member is an IPv6 prefix ...
          if(is_ipv6($member)) {
            // ... just store it along with the rest
            $route6_set_members[$member] = true;
          // If member is RS-ANY or ANY ...
          } elseif(is_any($member)) {
            // ... store ::/0
            $route_set_members['::/0'] = true;
          // Otherwise, member should be a route set.
          // So, unless already expanded ...
          } elseif(!isset($already_expanded[$member])) {
            // ... add it to the expansion list
            $expand_route6_sets[$member] = true;
            // ... set it as expanded to prevent loops
            $already_expanded[$member] = true;
          }
        }
      }
    }
  }

  // If our expanded route set has no members ...
  if(empty($route6_set_members))
    // ... return nothing
    return;

  // Return expanded route-set
  return array('route-set' => $route6_set_name,
               'mp-members' => array_keys($route6_set_members));
}

// ***************************** POLICY FUNCTIONS *****************************

function get_export_from_to($from_asn, $to_asn, &$servers=NULL)
{

  // Fetch source aut-num object
  $aut_num = aut_num($from_asn, $servers);
  if(empty($aut_num))
    return;

  // Get whatever source AS is exporting to target AS
  if(isset($aut_num['export'][$to_asn]))
    $exported = $aut_num['export'][$to_asn];
  // If target AS is missing from export attributes
  // look for wildcard AS-ANY ...
  elseif(isset($aut_num['export']['AS-ANY']))
    $exported = $aut_num['export']['AS-ANY'];
  // ... or ANY
  elseif(isset($aut_num['export']['ANY']))
    $exported = $aut_num['export']['ANY'];

  // If no wildcard is found among export attributes ...
  if(empty($exported))
    // ... we are not supposed to receive anything
    return;

  // If directly exporting prefixes
  // embedded into export attribute ...
  if(is_array($exported) || is_any($exported))
    // ... nothing more to be done here
    return $exported;

  // If exporting as-set ...
  if(preg_match('/^AS\-/i', $exported)) {
    // ... expand it into a full list of ASNs
    $as_set = as_set($exported, $servers);
    if(isset($as_set) && is_array($as_set))
      $exported = $as_set['members'];
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route_set = route_set($exported, $servers);
    if(isset($route_set) && is_array($route_set))
      $exported = $route_set['members'];
  }

  return $exported;
}

function get_mpexport_from_to($from_asn, $to_asn, &$servers=NULL)
{
  // Fetch source aut-num object
  $aut_num = aut_num($from_asn, $servers);
  if(empty($aut_num))
    return;

  // Get whatever source AS is exporting to target AS
  if(isset($aut_num['mp-export'][$to_asn]))
    $exported = $aut_num['mp-export'][$to_asn];
  // If target AS is missing from export attributes
  // look for wildcard AS-ANY ...
  elseif(isset($aut_num['mp-export']['AS-ANY']))
    $exported = $aut_num['mp-export']['AS-ANY'];
  // ... or ANY
  elseif(isset($aut_num['mp-export']['ANY']))
    $exported = $aut_num['mp-export']['ANY'];

  // If no wildcard is found among export attributes ...
  if(empty($exported))
    // ... we are not supposed to receive anything
    return;

  // If directly exporting prefixes
  // embedded into export attribute ...
  if(is_array($exported) || is_any($exported))
    // ... nothing more to be done here
    return $exported;

  // If exporting as-set ...
  if(preg_match('/^AS\-/i', $exported)) {
    // ... expand it into a full list of ASNs
    $as_set = as_set($exported, $servers);
    if(isset($as_set) && is_array($as_set))
      $exported = $as_set['members'];
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route6_set = route6_set($exported, $servers);
    if(isset($route6_set) && is_array($route6_set))
      $exported = $route6_set['mp-members'];
  }

  return $exported;
}

function get_announced_ipv4_prefixes($from_asn, $to_asn, &$servers=NULL)
{
  global $config;

  // If Whois servers' weren't given ...
  if(empty($servers))
    // ... use globally configured ones
    $servers = &$config['whois'];

  // Don't waste time ...
  if(empty($servers) || !is_array($servers))
    return;

  $exported = NULL;

  for($i = 0; $i < sizeof($servers); $i++) {
    // Get the list of exports
    // by <from_asn> to <to_asn>
    $exported = get_export_from_to($from_asn, $to_asn, $servers);
    // If query suceeded ...
    if(!empty($exported))
      // ... proceed to the next phase
      break;
    // Report failure
    debug_message("Query produced no usable results.");
    // Lower layer (whois_query() function) will
    // remove failed servers from the list.
    // Thus, if there's still at least one server
    // in the list, it is (probably) functional,
    // but hasn't produced expected results, so,
    // we will ...
    if(sizeof($servers) > 1) {
      //  ... move it back to the tail of the list ...
      array_push($servers, array_shift($servers));
      // ... and query the next server, if there is one
      debug_message("Trying the next server.");
    }
  }

  // If no exports could be found ...
  if(empty($exported))
    // ... abort
    return;

  // If export is AS-ANY or ANY ...
  if(is_any($exported))
    // return IPv4 default
    return array('0' => array('0.0.0.0/0'));

  // Make sure this is always an array
  // even if it contains a single element
  if(!is_array($exported))
    $exported = array($exported);

  // Retrieve route objects. Exports can either be
  // a list of IPv4 prefixes or a list of AS numbers
  $routes = is_ipv4($exported) ? 
              whois_query($exported, 'route', NULL, $servers):
              whois_query($exported, 'route', 'origin', $servers);

  if(empty($routes))
    return;

  $announced = array();

  foreach($routes as $prefix => $objects) {
    // Make sure this is always an array even
    // if it contains a single route object
    if(is_rpsl_object($objects))
      $objects = array($objects);
    // Process route objects
    foreach($objects as $route) {
      // Route object must have the origin attribute
      if(empty($route['origin']))
        continue;
      // Make sure origin AS is uppercase
      $asn = strtoupper($route['origin']);
      // Skip prefix if originated by target ASN.
      // No point exporting it to itself.
      if($asn == $to_asn)
        continue;
      // Store prefixes into announced list
      $announced[$asn][] = $prefix;
    }
  }

  return $announced;
}

function get_announced_ipv6_prefixes($from_asn, $to_asn, &$servers=NULL)
{
  global $config;

  // If Whois servers' weren't given ...
  if(empty($servers))
    // ... use globally configured ones
    $servers = &$config['whois'];

  // Don't waste time ...
  if(empty($servers) || !is_array($servers))
    return;

  $exported = NULL;

  for($i = 0; $i < sizeof($servers); $i++) {
    // Get the list of exports
    // by <from_asn> to <to_asn>
    $exported = get_mpexport_from_to($from_asn, $to_asn, $servers);
    // If query suceeded ...
    if(!empty($exported))
      // ... proceed to the next phase
      break;
    // Report failure
    debug_message("Query produced no usable results.");
    // Lower layer (whois_query() function) will
    // remove failed servers from the list.
    // Thus, if there's still at least one server
    // in the list, it is (probably) functional,
    // but hasn't produced expected results, so,
    // we will ...
    if(sizeof($servers) > 1)
      //  ... move it back to the tail of the list
      array_push($servers, array_shift($servers));
      // ... and query the next server, if there is one
      debug_message("Trying the next server.");
  }

  // If no exports could be found ...
  if(empty($exported))
    // ... abort
    return;

  // If export is AS-ANY or ANY ...
  if(is_any($exported))
    // return IPv6 default
    return array('0' => array('::/0'));

  // Make sure this is always an array
  // even if it contains a single element
  if(!is_array($exported))
    $exported = array($exported);

  // Retrieve route6 objects. Exports can either be
  // a list of IPv6 prefixes or a list of AS numbers
  $routes = is_ipv6($exported) ? 
              whois_query($exported, 'route6', NULL, $servers):
              whois_query($exported, 'route6', 'origin', $servers);

  if(empty($routes))
    return;

  $announced = array();

  foreach($routes as $prefix => $objects) {
    // Make sure this is always an array even
    // if it contains a single route object
    if(is_rpsl_object($objects))
      $objects = array($objects);
    // Process route6 objects
    foreach($objects as $route6) {
      // Route6 object must have the origin attribute
      if(empty($route6['origin']))
        continue;
      // Make sure origin AS is uppercase
      $asn = strtoupper($route6['origin']);
      // Skip prefix if originated by target ASN.
      // No point exporting it to itself.
      if($asn == $to_asn)
        continue;
      // Store prefixes into announced list
      $announced[$asn][] = $prefix;
    }
  }

  return $announced;
}

?>
