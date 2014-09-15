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

include_once $config['includes_dir'].'/tools.inc.php';

// ************************ LOW LEVEL WHOIS FUNCTIONS *************************

function whois_request($search, $options='')
{
  global $config;

  // Don't waste my time
  if(empty($search))
    return;

  // Whois server type ('irr', 'ripe')
  // (default: 'ripe')
  $type = (!empty($config['whois_type'])) ?
              $config['whois_type']:"ripe";

  // Whois server
  // (default: whois.ripe.net)
  $host = (!empty($config['whois_server'])) ?
              $config['whois_server']:"whois.ripe.net";

  // Whois TCP port
  // (default: 43)
  $port = (!empty($config['whois_port'])) ?
              $config['whois_port']:43;

  // Address families for connection (AF_INET, AF_INET6)
  // (default: AF_INET6, AF_INET)
  $address_families = (!empty($config['whois_address_family'])) ?
                          $config['whois_address_family']:
                          array(AF_INET6, AF_INET);

  // Socket operations (connect/read/write) timeout
  // (default: 5 seconds)
  $socket_timeout = (!empty($config['whois_sock_timeout'])) ?
                        $config['whois_sock_timeout']:5;

  // Query timeout (max time single query can last)
  // (default: 300 seconds)
  $query_timeout = (!empty($config['whois_query_timeout'])) ?
                       $config['whois_query_timeout']:300;

  // List of whois server addresses should persist
  // between calls in order to act as a DNS cache
  static $addrs;

  // If 'DNS cache' is empty ...
  if(empty($addrs)) {
    // Create a new list of addresses
    $addrs = array();
    // Whois server specified as IPv4 address ?
    if(is_ipv4($host)) {
      $addrs[AF_INET] = $host;
    // Whois server specified as IPv6 address ?
    } elseif(is_ipv6($host)) {
      $addrs[AF_INET6] = $host;
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
              $addrs[AF_INET] = $record['ip'];
              break;
            case 'AAAA':
              $addrs[AF_INET6] = $record['ipv6'];
              break;
          }
        }
      }
    }
    // Nothing to do if hostname failed to resolve
    if(empty($addrs))
      return;
  }

  // Determine if and how to begin and end
  // persistent connection (bulk mode)
  switch($type) {
    // Whois server is 100% RIPE compatibile
    // (which is whois.ripe.net only, AFAIK)
    case 'ripe':
      $begin = "-k";
      $end = "-k";
      break;
    // Whois server is based on IRRd software.
    // It's compatibile with RIPE for the most
    // part, but persistant connection mode is
    // handled slightly differently
    case 'irrd':
      $begin = "!!";
      $end = "q";
      break;
  }

  // Prepared queries will be stored here
  // and then taken from this array and
  // executed in the same order in which
  // they were placed here
  $queries = array();

  // Make sure search is always an array
  // even if it contains a single element
  if(!is_array($search))
    $search = array($search);

  // Bulk mode enabled ?
  if(!empty($begin) && !empty($end)) {
    // Prepare bulk query by concatenating
    // all lookup strings prepended with
    // whois options. In bulk mode we will
    // perform a single query asking for
    // many RPSL objects at once
    $queries[] = $options." ".implode("\n".$options." ", $search)."\n";
  // Bulk mode is disabled ...
  } else {
    // Without bulk mode we will perform as many queries
    // as there are RPSL objects we want to retrieve
    foreach(array_unique($search) as $lookup_string)
      // Prepare each query by prepending
      // whois options to the lookup string
      $queries[] = $options." ".$lookup_string."\n";
  }

  // Make sure address families are always in an array
  // even if only a single address family is specified
  if(!is_array($address_families))
    $address_families = array($address_families);

  // This will hold the response to our search
  // either retrieved all at once, in bulk mode
  // or built by fetching and appending object
  // by object, without bulk mode
  $response = '';

  // Run all queries
  foreach($queries as $query) {

    // First, we need to connect
    $sock = false;

    // Create socket and try to connect
    foreach($address_families as $af) {
      // No address for this address family ...
      if(empty($addrs[$af]))
        // ... try the next address family
        continue;

      // Create new socket
      $sock = socket_create($af, SOCK_STREAM, SOL_TCP);
      if($sock === FALSE)
        continue;

      // Set socket to non-blocking mode
      socket_set_nonblock($sock);

      // Moment in which connection attempts timeout
      $connect_timeout = time() + $socket_timeout;

      // Keep trying to connect until success or timeout
      while(socket_connect($sock, $addrs[$af], $port) === FALSE) {
        // Since we are in non-blocking mode, socket_connect()
        // will keep returning FALSE until we are connected
        // even if there is no true error condition. During
        // that time, error codes we may encounter are EALREADY
        // and EINPROGRESS indicating that connection is pending,
        // so we should simply ignore them and keep trying to
        // get to the point where socket_connect() will return
        // TRUE. Of course, if we notice other errors, we should
        // handle them.
        switch(socket_last_error($sock)) {
          case EALREADY:
          case EINPROGRESS:
            // On connect timeout, abort
            if(time() > $connect_timeout) {
              socket_close($sock);
              $sock = false;
              continue 3;
            }
            // Wait 1 ms
            usleep(1000);
            break;
          // On other errors, abort
          default:
            socket_close($sock);
            $sock = false;
            continue 3;
        }
      }

      // We are connected now,
      // so we are done here
      break;
    }

    // Connection failed for whatever reason ?
    if($sock === FALSE)
      // Abort !
      return;

    // If bulk mode is enabled ...
    if(!empty($begin) && !empty($end)) {
      // ... begin persistent connection
      if(socket_write($sock, $begin."\n") === FALSE) {
        socket_close($sock);
        return;
      }
    }

    // Query cannot last beyond this time
    $query_deadline = time() + $query_timeout;

    // Total size of the query
    $size = strlen($query);
    // Amount of data sent
    $sent = 0;

    // Socket to monitor for read readiness
    $in_sock = array($sock);
    // Socket to monitor for write readiness
    $out_sock = array($sock);

    // Until query timeout ...
    while(time() < $query_deadline) {
      $read_ready = $in_sock;
      $write_ready = $out_sock;
      $null = NULL;
      // Wait for socket to become ready
      $ready = socket_select($read_ready, $write_ready, $null, 1);
      // Error ?
      if($ready === FALSE) {
        socket_close($sock);
        return;
      }
      // If socket is ready ...
      if($ready > 0) {
        // .. for writing ?
        if(!empty($write_ready)) {
          if(in_array($sock, $write_ready)) {
            // As long as query hasn't been fully sent ...
            if($sent < $size) {
              // ... write a chunk
              $written = socket_write($sock, substr($query, $sent), 1000);
              // On error - abort
              if($written === FALSE) {
                socket_close($sock);
                return;
              }
              // Adjust the total amount sent
              $sent += $written;
              // Now, if entire query has been sent ...
              if($sent >= $size) {
                // ... stop monitoring socket
                // for write readiness
                $out_sock = NULL;
              }
            }
          }
        }
        // ... for reading ?
        if(!empty($read_ready)) {
          if(in_array($sock, $read_ready)) {
            // Read a chunk of response
            $chunk = socket_read($sock, 10000);
            // On error - abort
            if($chunk === FALSE) {
              socket_close($sock);
              return;
            }
            // If we got nothing, we are done
            if(empty($chunk))
              break;
            // Append chunk to the response
            $response .= $chunk;
          }
        }
      // Socket became idle ...
      } else {
        // If bulk mode is enabled ...
        if(empty($out_sock) && !empty($begin) && !empty($end))
          // ... end persistent connection
          socket_write($sock, $end."\n");
      }
    }

    // This newline is extremely important
    // in order to separate objects when
    // fetching them one by one without
    // bulk mode. Has no impact on bulk
    // queries, so it doesn't hurt.
    $response .= "\n";
  }

  // Close the connection
  socket_close($sock);

  // Return cumulative response
  return $response;
}

// **************************** QUERY FUNCTIONS *******************************

function query_whois($search, $type=NULL, $attr=NULL)
{
  global $config;

  // Don't waste my time ...
  if(empty($search))
    return;

  //
  // Leave out contact information
  // to avoid RIPE's daily limit ban:
  //
  //   http://www.ripe.net/data-tools/db/faq/faq-db/why-did-you-receive-the-error-201-access-denied
  //
  $options = '-r';
  // Preferred whois source
  if(!empty($config['whois_source']))
    $options .= ' -s'.$config['whois_source'];
  // Preferred object type
  if(!empty($type))
    $options .= ' -T'.$type;
  // Inverse lookup by this attribute
  if(!empty($attr))
    $options .= ' -i'.$attr;

  // Query whois server
  $response = whois_request($search, $options);
  // Got nothing - aborting
  if(empty($response))
    return;

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
    if(preg_match('/^\s*([^\s:]+):\s*(.*)/i', $line, $m)) {
      // Skip unused attributes
      switch($m[1]) {
        case 'descr':
        case 'remarks':
        case 'mnt-by':
        case 'mnt-ref':
        case 'mnt-lower':
        case 'mnt-routes':
        case 'admin-c':
        case 'tech-c':
        case 'source':
        case 'org':
          unset($attr);
          continue 2;
        default:
          $attr = $m[1];
          $value = $m[2];
          break;
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

// ************************** RPSL OBJECT FUNCTIONS ***************************

function aut_num($asn)
{
  // Don't waste time ...
  if(empty($asn))
    return;

  // Uppercase the ASN
  $asn = strtoupper($asn);

  // Fetch aut-num object
  $res = query_whois($asn, 'aut-num');
  if(empty($res) || !is_rpsl_object($res[$asn]))
    return;

  // This is our raw aut-num object
  $object = $res[$asn];

  // Copy basic aut-num object attributes
  // (only the important ones)
  $aut_num = array(
    'aut-num' => $asn,
    'as-name' => strtoupper($object['as-name'])
  );

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
        // AS, AS-SET or ANY ?
        elseif(!empty($m[2]))
          // Make sure this is always uppercase
          $what = strtoupper($m[2]);
      }
      // Store dumbed down version of import attribute
      if(!empty($what))
        $aut_num['import'][$from] = $what;
    }
  }
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
        // AS, AS-SET or ANY ?
        elseif(!empty($m[2]))
          // Make sure this is always uppercase
          $what = strtoupper($m[2]);
      }
      // Store dumbed down version of export attribute
      if(!empty($what))
        $aut_num['export'][$to] = $what;
    }
  }
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
        // AS, AS-SET or ANY ?
        elseif(!empty($m[2]))
          // Make sure this is always uppercase
          $what = strtoupper($m[2]);
      }
      // Store dumbed down version of import attribute
      if(!empty($what))
        $aut_num['mp-import'][$from] = $what;
    }
  }
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
        // AS, AS-SET or ANY ?
        elseif(!empty($m[2]))
          // Make sure this is always uppercase
          $what = strtoupper($m[2]);
      }
      // Store dumbed down version of export attribute
      if(!empty($what))
        $aut_num['mp-export'][$to] = $what;
    }
  }

  return $aut_num;
}

function as_set($as_set_name)
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
    $as_sets = query_whois(array_keys($expand_as_sets), 'as-set');
    if(empty($as_sets))
      break;

    // Begin with an empty list of AS sets to expand.
    // This list will be used in the next iteration.
    $expand_as_sets = array();

    // Collect all members from all found AS set objects
    foreach(array_values($as_sets) as $as_set) {

      // Proper AS set object must have members attribute(s)
      if(empty($as_set) || empty($as_set['members']))
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
          // If member is a simple ASN ...
          if(is_asn($member)) {
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

function route_set($route_set_name)
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
    $route_sets = query_whois(array_keys($expand_route_sets), 'route-set');
    if(empty($route_sets))
      break;

    // Begin with an empty list of route sets to expand.
    // This list will be used in the next iteration.
    $expand_route_sets = array();

    // Collect all members from all found route set objects
    foreach(array_values($route_sets) as $route_set) {

      // Proper route set object must have members attribute(s)
      if(empty($route_set) || empty($route_set['members']))
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

function route6_set($route6_set_name)
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
    $route6_sets = query_whois(array_keys($expand_route6_sets), 'route-set');
    if(empty($route6_sets))
      break;

    // Begin with an empty list of route sets to expand.
    // This list will be used in the next iteration.
    $expand_route6_sets = array();

    // Collect all members from all found route set objects
    foreach(array_values($route6_sets) as $route6_set) {

      // Proper route set object must have members attribute(s)
      if(empty($route6_set) || empty($route6_set['members']))
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

function get_export_from_to($from_asn, $to_asn)
{
  // Fetch source aut-num object
  $aut_num = aut_num($from_asn);
  if(!isset($aut_num) ||
     !is_array($aut_num) ||
     !isset($aut_num['export']) ||
     !isset($aut_num['export'][$to_asn]))
    return;

  // Get whatever source AS is exporting to target AS
  $exported = $aut_num['export'][$to_asn];
  if(!isset($exported))
    return;

  // If directly exporting prefixes
  // embedded into export attribute ...
  if(is_array($exported))
    // ... nothing more to be done here
    return $exported;

  // Ignore ANY
  if(preg_match('/^ANY$/i', $exported))
    return;

  // If exporting as-set ...
  if(preg_match('/^AS\-/i', $exported)) {
    // ... expand it into a full list of ASNs
    $as_set = as_set($exported);
    if(isset($as_set) && is_array($as_set))
      $exported = $as_set['members'];
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route_set = route_set($exported);
    if(isset($route_set) && is_array($route_set))
      $exported = $route_set['members'];
  }

  return $exported;
}

function get_mpexport_from_to($from_asn, $to_asn)
{
  // Fetch source aut-num object
  $aut_num = aut_num($from_asn);
  if(!isset($aut_num) ||
     !is_array($aut_num) ||
     !isset($aut_num['mp-export']) ||
     !isset($aut_num['mp-export'][$to_asn]))
    return;

  // Get whatever source AS is exporting to target AS
  $exported = $aut_num['mp-export'][$to_asn];
  if(!isset($exported))
    return;

  // If directly exporting prefixes
  // embedded into export attribute ...
  if(is_array($exported))
    // ... nothing more to be done here
    return $exported;

  // Ignore ANY
  if(preg_match('/^ANY$/i', $exported))
    return;

  // If exporting as-set ...
  if(preg_match('/^AS\-/i', $exported)) {
    // ... expand it into a full list of ASNs
    $as_set = as_set($exported);
    if(isset($as_set) && is_array($as_set))
      $exported = $as_set['members'];
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route6_set = route6_set($exported);
    if(isset($route6_set) && is_array($route6_set))
      $exported = $route6_set['mp-members'];
  }

  return $exported;
}

function get_announced_ipv4_prefixes($from_asn, $to_asn)
{
  global $config;

  // Get the list of exports
  // by <from_asn> to <to_asn>
  $exported = get_export_from_to($from_asn, $to_asn);
  if(!isset($exported))
    return;

  // Make sure this is always an array
  // even if it contains a single element
  if(!is_array($exported))
    $exported = array($exported);

  $announced = array();

  // Retrieve route objects. Exports can either be
  // a list of IPv4 prefixes or a list of AS numbers
  $routes = is_ipv4($exported) ? 
              query_whois($exported, 'route'):
              query_whois($exported, 'route', 'origin');

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

function get_announced_ipv6_prefixes($from_asn, $to_asn)
{
  // Get the list of exports
  // by <from_asn> to <to_asn>
  $exported = get_mpexport_from_to($from_asn, $to_asn);
  if(!isset($exported))
    return;

  // Make sure this is always an array
  // even if it contains a single element
  if(!is_array($exported))
    $exported = array($exported);

  $announced = array();

  // Retrieve route6 objects. Exports can either be
  // a list of IPv6 prefixes or a list of AS numbers
  $routes = is_ipv6($exported) ? 
              query_whois($exported, 'route6'):
              query_whois($exported, 'route6', 'origin');

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
