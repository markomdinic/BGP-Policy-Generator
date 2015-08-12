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

// ***************** LOW LEVEL RPSL OBJECT PARSING FUNCTIONS ******************

function parse_aut_num($object)
{
  // Don't waste time ...
  if(empty($object) ||
     !(isset($object['export']) ||
       isset($object['mp-export'])))
    return;

  // Begin constructing new aut-num object
  $aut_num = array();

/*
  // Copy import attribute(s)
  if(isset($object['import'])) {
    $imports = is_array($object['import']) ?
                 $object['import']:array($object['import']);
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
                 $object['export']:array($object['export']);
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
                 $object['mp-import']:array($object['mp-import']);
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
                 $object['mp-export']:array($object['mp-export']);
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

  // Object is not complete ?
  if(empty($aut_num) ||
     !(isset($aut_num['export']) ||
       isset($aut_num['mp-export'])))
    return;

  // Add the rest of attributes of interest
  $aut_num['aut-num'] = strtoupper($object['aut-num']);

  // Done
  return $aut_num;
}

function parse_as_set($object)
{
  // Don't waste time ...
  if(empty($object) ||
     !(isset($object['as-set']) &&
       isset($object['members'])))
    return;

  // Raw member attributes
  $raw_members = is_array($object['members']) ?
                   $object['members']:array($object['members']);

  // Parsed member attributes
  $parsed_members = array();

  // Parse raw member attributes
  foreach($raw_members as $member) {
    // Skip parsing errors
    if(empty($member))
      continue;
    // String might contain comma-separated members list
    foreach(preg_split('/[,;:]/', strtoupper($member)) as $member) {
      // Strip leading and trailing trash
      if(!preg_match('/([^\s#]+)/', $member, $m))
        continue;
      // Store parsed member
      if(!empty($m[1]))
        // By storing members as array keys
        // we eliminate duplicate entries
        $parsed_members[$m[1]] = true;
    }
  }

  if(empty($parsed_members))
    return;

  // Format and return final object
  return array(
    'as-set' => strtoupper($object['as-set']),
    'members' => array_keys($parsed_members)
  );
}

function parse_route_set($object)
{
  // Don't waste time ...
  if(empty($object) ||
     !(isset($object['route-set']) &&
       isset($object['members'])))
    return;

  // Raw member attributes
  $raw_members = is_array($object['members']) ?
                   $object['members']:array($object['members']);

  // Parsed member attributes
  $parsed_members = array();

  // Parse raw member attributes
  foreach($raw_members as $member) {
    // Skip parsing errors
    if(empty($member))
      continue;
    // String might contain comma-separated members list
    foreach(preg_split('/(?:\^[^,\s]*)?\s*[,\s]\s*/', strtoupper($member)) as $member) {
      // Strip leading and trailing trash
      if(!preg_match('/([^\s#]+)/', $member, $m))
        continue;
      // Store parsed member
      if(!empty($m[1]))
        // By storing members as array keys
        // we eliminate duplicate entries
        $parsed_members[$m[1]] = true;
    }
  }

  if(empty($parsed_members))
    return;

  // Format and return final object
  return array(
    'route-set' => strtoupper($object['route-set']),
    'members' => array_keys($parsed_members)
  );
}

function parse_route($object)
{
  // Don't waste time ...
  if(empty($object) ||
     !(isset($object['route']) &&
       isset($object['origin'])))
    return;

  return array(
    'route' => $object['route'],
    'origin' => strtoupper($object['origin'])
  );
}

function parse_route6($object)
{
  // Don't waste time ...
  if(empty($object) ||
     !(isset($object['route6']) &&
       isset($object['origin'])))
    return;

  return array(
    'route' => strtolower($object['route']),
    'origin' => strtoupper($object['origin'])
  );
}

// ************************ LOW LEVEL WHOIS FUNCTIONS *************************

function whois_query_server($server, $search_objects, $object_type=NULL, $inverse_lookup_attr=NULL)
{
  // If search string(s) are missing ...
  if(empty($search_objects))
    // ... return an empty result
    return;

  // Make sure search is always an array
  // even if it contains a single element
  if(!is_array($search_objects))
    $search_objects = array($search_objects);

  // If Whois server parameters are missing,
  // explicitly return FALSE, to signal
  // that something went wrong
  if(empty($server) || !is_array($server))
    return false;

  // Whois server host
  // (default: none)
  $host = $server['server'];
  if(empty($host))
    return false;

  $host = strtolower($host);

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

  // Whois server TCP port
  // (default: 43)
  $port = is_port($server['port']) ?
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

  // Socket operations (connect/read/write) timeout
  // (default: 5 seconds)
  $socket_timeout = is_positive($server['sock_timeout']) ?
                      $server['sock_timeout']:5;

  // Timeout parameter for socket_set_option SO_SNDTIMEO and SO_RCVTIMEO
  $snd_rcv_timeout = array('sec' => $socket_timeout, 'usec' => 0);

  // Whois query size (max number of objects per query in bulk mode)
  // (default: 1000)
  $query_size = is_positive($server['query_size']) ?
                  $server['query_size']:1000;

  // Query timeout (max time a single query can last)
  // (default query timeout in bulk mode is 30 min)
  $query_timeout = 1800;

  // Whois server type ('irrd', 'ripe')
  // (default: none)
  switch($server['type']) {
    // Whois server is 100% RIPE compatibile
    case 'ripe':
      // Enable bulk mode
      $begin = "-k\n";
      $end = "-k\n";
      debug_message("Using RIPE-compatibile bulk query mode.");
      break;
    // Whois server is based on IRRd software.
    // It's compatibile with RIPE for the most
    // part, but persistant connection mode is
    // handled slightly differently
    case 'irrd':
      // Enable bulk mode
      $begin = "!!\n";
      $end = "q\n";
      debug_message("Using irrd-compatibile bulk query mode.");
      break;
    // Other/unknown/'traditional' whois server
    default:
      // Normal mode - no bulk mode by default
      $begin = "";
      $end = "";
      // Force a single object per query in normal mode
      $query_size = 1;
      // Default query timeout in normal mode is 1 min
      $query_timeout = 60;
      debug_message("Using normal query mode.");
      break;
  }

  // Use user-defined query timeout, if any
  if(is_positive($server['query_timeout']))
    $query_timeout = $server['query_timeout'];

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
  if(!empty($object_type))
    $options .= ' -T'.$object_type;

  // Inverse lookup by this attribute
  if(!empty($inverse_lookup_attr))
    $options .= ' -i'.$inverse_lookup_attr;

  // Prepared queries will be stored here
  $queries = array();

  // If bulk mode is enabled multiple queries will be executed
  // query_size number of objects per query. In normal mode,
  // there is a single object per query, single query per
  // connection
  for($prepared = 0, $num_obj = sizeof($search_objects); $prepared < $num_obj; $prepared += $query_size)
    // Prepare a query of query_size number of objects.
    $queries[] = $begin.$options." ".implode("\n".$options." ", array_slice($search_objects, $prepared, $query_size))."\n".$end;

  debug_message("Querying server ".$host." ...");

  // Parsed objects go here
  $objects = array();

  // Required by socket_select()
  $none = NULL;

  // Not yet connected
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
        // Create a TCP socket
        $sock = socket_create($af, SOCK_STREAM, SOL_TCP);
        if($sock === FALSE)
          continue;
        // Set socket operations timeout
        socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, $snd_rcv_timeout);
        socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, $snd_rcv_timeout);
        // Make socket non blocking
        socket_set_nonblock($sock);
        // Connect attempts cannot go on
        // beyond connect_deadline
        $connect_deadline = time() + $socket_timeout;
        // Keep trying to connect until timeout
        while(time() < $connect_deadline) {
          // Initial call will start a connect operation,
          // while the subsequent calls will just return
          // the status of the initiated connect operation
          if(@socket_connect($sock, $addrs[$host][$af], $port) !== FALSE)
            // If connected successfully, we can proceed
            break 2;
          // On error ...
          if(!in_array(socket_last_error($sock), array(0, EALREADY, EINPROGRESS)))
            // ... abort current connect operation
            // and try the next address family
            break;
          // If a connect operation is in progress,
          // wait a bit and then go back to check
          // for status, until operation is complete
          // or we break the connect deadline
          sleep(1);
        }
        // Not connected
        $sock = false;
      }

      // Failed to connect ?
      if($sock === FALSE)
        // Abort !
        return false;

      // Clear previous socket errors
      socket_clear_error($sock);

    }

    // A single query cannot last
    // longer than query_timeout,
    // that is, beyond query_deadline
    $query_deadline = time() + $query_timeout;

    // Send whois query
    for($sent = 0, $total_sent = 0, $query_length = strlen($query);
        $total_sent < $query_length;
        $total_sent += $sent) {

      // Query timeout ?
      if(time() > $query_deadline) {
        debug_message("Query timed out.");
        socket_shutdown($sock, 2);
        socket_close($sock);
        return false;
      }

      // Prepare socket for monitoring
      $write_socks = array($sock);

      // Wait for our socket to become ready,
      // but no longer than 1 second
      $num_ready = socket_select($none, $write_socks, $none, 1);

      // Error ?
      if($num_ready === FALSE) {
        socket_close($sock);
        return false;
      }

      // Connection is idle ?
      if($num_ready == 0)
        continue;

      // Send as much as possible in a single call
      $sent = socket_send($sock, substr($query, $total_sent), $query_length - $total_sent, 0);

      // Error ?
      if($sent === FALSE) {
        socket_close($sock);
        return false;
      }

    }

    // Prepare response data storage
    $response = "";

    // Prepare object parsing variables
    $object = NULL;
    $type = NULL;
    $key = NULL;
    $attr = NULL;
    $value = NULL;
    $skip = false;

    // Raise our receive & parse flag
    $receive = true;

    // Read and parse whois response
    while($receive) {

      // Query timeout ?
      if(time() > $query_deadline) {
        debug_message("Query timed out.");
        socket_shutdown($sock, 2);
        socket_close($sock);
        return false;
      }

      // Prepare socket for monitoring
      $read_socks = array($sock);

      // Wait for our socket to become ready,
      // but no longer than 1 second
      $num_ready = socket_select($read_socks, $none, $none, 1);

      // Error ?
      if($num_ready === FALSE) {
        socket_close($sock);
        return false;
      }

      // Connection is idle ?
      if($num_ready == 0)
        continue;

      // Socket is ready, there's has data to be read

      // Drain the socket
      while($receive) {

        // Get a part of response
        $num = socket_recv($sock, $buffer, 1000000, 0);

        // Read failed ?
        if($num === FALSE) {
          // What exactly happened ?
          switch(socket_last_error($sock)) {
            // Nothing to read at the moment ...
            case EWOULDBLOCK:
              break 2;
            // Connection closed ...
            case ECONNRESET:
              break;
            default:
              // Otherwise it is an error
              socket_close($sock);
              return false;
          }
        }

        // If we recived data ...
        if($num > 0) {
          // ... append it to the rest of response data
          $response .= $buffer;
        // If there is no more data to read ...
        } else {
          // ... in case last returned object was not terminated
          // with a trailing empty line, we will insert an empty
          // line to explicitly mark the end of current object
          $response = "\n";
          // ... and we are done, drop the flag, end loop(s)
          $receive = false;
        }

        // Split response data into lines, if possible.
        // Resulting array will have N+1 elements, where
        // N is the number of complete lines, and +1
        // is the last, incomplete line
        $lines = explode("\n", $response);

        // Once we parse extracted lines, we will resume
        // accumulating response data from the last,
        // incomplete line
        $response = array_pop($lines);

        // Parse extacted lines
        foreach($lines as $line) {

          // Object ends on an empty line
          if($line === "") {
            // If object type and raw object data exist ...
            if(!empty($type) && !empty($object)) {
              // ... look for parser for that particular object type
              $parser = 'parse_'.str_replace('-', '_', $type);
              // If parser exists ...
              if(function_exists($parser))
                // ... invoke it to replace raw object
                // with a more refined, parsed form
                $object = call_user_func($parser, $object);
            }
            // If object and it's primary key are defined ...
            if(!empty($key) && !empty($object)) {
              // ... and object already exists in the list ...
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
            $object = NULL;
            $type = NULL;
            $key = NULL;
            $attr = NULL;
            $value = NULL;
            $skip = false;
            continue;
          }

          // Some part of this processing loop determined
          // that current object should be skipped ...
          if($skip)
            continue;

          // Skip comments
          if(preg_match('/^\s*%/', $line))
            continue;

          // Scan current line looking for "attribute: value"
          if(preg_match('/^([^\s:]+):\s*(.*)$/', $line, $m)) {
            $attr = strtolower($m[1]);
            switch($attr) {
              // Pick attributes we need
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
                $value = $m[2];
                break;
              // Skip attributes we don't need
              default:
                $attr = NULL;
                continue 2;
            }

            // If no object is currently in construction ...
            if(empty($object) && !empty($attr)) {
              // ... and the specific attribute was requested,
              // but doesn't match the source object type ...
              if(!empty($object_type) && $object_type != $attr) {
                // ... skip source lines until the next object
                $skip = true;
                continue;
              }
              // Otherwise, begin constructing a new object
              // and remember object's type and primary key
              $object = array();
              $type = $attr;
              $key = $value;
            }

            // Store attribute into the object in construction
            if(is_array($object)) {
              // If attribute already exists ...
              if(isset($object[$attr])) {
                // ... and is already an array ...
                if(is_array($object[$attr]))
                  // ... add value along with others
                  $object[$attr][] = $value;
                // Otherwise, convert it to array ...
                else
                  // ... which will now hold both
                  // previous and the current value
                  $object[$attr] = array($object[$attr], $value);
              // If attribute doesn't exist, create it
              } else
                $object[$attr] = $value;
            }

          // Line is a continuation of a multiline value ?
          } elseif(!empty($attr)) {

            // Remove trash from the current line
            $value = trim($line);
            // Append trimmed current line to the existing attribute's value
            if(!empty($object) && is_array($object)) {
              // If attribute is an array ...
              if(is_array($object[$attr])) {
                // ... and array isn't empty
                // (shouldn't be at this point) ...
                $last = count($object[$attr]) - 1;
                if($last >= 0)
                  // ... append to the last stored value
                  $object[$attr][$last] .= $value;
              // Otherwise, if attribute holds a single value ...
              } else
                // ... simply append to it
                $object[$attr] .= $value;
            }

          }

        }

      }

    }

    // Close connection
    socket_close($sock);
    $sock = false;

  }

  // At this point, all queries have been executed
  return $objects;
}

function whois_query($search_objects, $object_type=NULL, $inverse_lookup_attr=NULL, &$servers=NULL)
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
    $objects = whois_query_server($servers[0],
                                  $search_objects,
                                  $object_type,
                                  $inverse_lookup_attr);
    // If query failed ...
    if($objects === false) {
      if(isset($servers[0]['server']) &&
         !empty($servers[0]['server']))
        debug_message("Removing failed server ".$servers[0]['server']." from the list.");
      else
        debug_message("Removing invalid server from the list. Check your configuration ?");
      // ... remove failed server from the list
      array_shift($servers);
      // ... try the next server
      continue;
    }
    // Otherwise, we are done
    return $objects;
  }

  // If we reached this point,
  // we have no usable servers
  return false;
}

// ******************** HIGH LEVEL RPSL OBJECT FUNCTIONS **********************

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

  return is_rpsl_object($res[$asn]) ?
                $res[$asn]:$res[$asn][0];
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

      // Each entry in the array of as-sets represents
      // a single as-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same as-set provided by different
      // sources in the same order sources were searched.
      // Sources are searched in descending order of
      // significance, thus we will simply pick the first
      // (most significant) version of this as-set.
      $as_set = is_rpsl_object($object) ? $object:$object[0];
      if(empty($as_set))
        continue;

      // The list of unique members of current AS set
      $members = is_array($as_set['members']) ?
                   $as_set['members']:array($as_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
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

      // Each entry in the array of route-sets represents
      // a single route-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same route-set provided by different
      // sources in the same order sources were searched.
      // Sources are searched in descending order of
      // significance, thus we will simply pick the first
      // (most significant) version of this route-set.
      $route_set = is_rpsl_object($object) ? $object:$object[0];
      if(empty($route_set))
        continue;

      // The list of unique members of current route set
      $members = is_array($route_set['members']) ?
                   $route_set['members']:array($route_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
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

      // Each entry in the array of route-sets represents
      // a single route-set. However, if searching multiple
      // sources, each entry can be an array of different
      // versions of the same route-set provided by different
      // sources in the same order sources were searched.
      // Sources are searched in descending order of
      // significance, thus we will simply pick the first
      // (most significant) version of this route-set.
      $route6_set = is_rpsl_object($object) ? $object:$object[0];
      if(empty($route6_set))
        continue;

      // The list of unique members of current route set
      $members = is_array($route6_set['members']) ?
                   $route6_set['members']:array($route6_set['members']);

      // Recursively copy and expand member attributes
      foreach($members as $member) {
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
      // Get route's origin
      $asn = $route['origin'];
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
      // Get route's origin
      $asn = $route6['origin'];
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
