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

function whois_connect($server, $port=NULL, $timeout=NULL, $delay=NULL)
{
  global $config;

  // Don't waste my time
  if(empty($server))
    return;

  // Set default parameters
  if(!isset($port))
    $port = $config['whois_port'];
  if(!isset($timeout))
    $timeout = $config['whois_timeout'];
  if(!isset($delay))
    $delay=$config['whois_delay'];

  // Resolve RIS whois server host
  $host = gethostbyname($server);

  // Create a new socket
  $sock = stream_socket_client("tcp://".$host.":".$port, $errno, $errstr, $timeout);
  if($sock === FALSE)
    return;

  // Set stream to non-blocking
  stream_set_blocking($sock, 0);
  // Set stream delay timeout
  stream_set_timeout($sock, $delay);

  return $sock;
}

function whois_request($sock, $query, $timeout=NULL)
{
  global $config;

  // Don't waste my time
  if(!isset($sock) || empty($query))
    return;

  // Set default timeout if not given explicitly
  if(!isset($timeout))
    $timeout = $config['whois_timeout'];

  // Execute whois query
  fwrite($sock, $query);

  $response = '';

  // Read operation cannot last beyond this timestamp
  $expire_timestamp = time() + $timeout;
  // Read response until EOF or timeout
  while(!feof($sock)) {
     // If timed out, abort
     if(time() > $expire_timestamp)
       break;
     // Get a piece of response
     $chunk = fgets($sock, 128);
     // Append piece to the receive buffer
     if(!empty($chunk))
       $response .= $chunk;
  }

  // Close connection
  fclose($sock);

  return $response;
}

// **************************** QUERY FUNCTIONS *******************************

function query_ris($query, $type=NULL)
{
  global $config;

  // Don't waste my time ...
  if(empty($query))
    return;

  // Connect to RIPE RIS server
  $sock = whois_connect($config['whois_ris_server']);
  if(!isset($sock))
    return;

  // Query RIS server
  // -k   request persistant connection for bulk queries
  // -F   request short format response
  $response = whois_request($sock, "-k -F\n".implode("\n", $query)."\n-k\n");

  $prefixes = array();

  // Parse raw output
  foreach(explode("\n", $response) as $line) {

    // Skip comments
    if(preg_match('/^\s*%/', $line))
      continue;

    // Looking for "<asn> <prefix> ..." line
    if(preg_match('/^\s*(?:AS)?(\d+)\s+(\S+)\s+/i', $line, $m)) {

      // Matching data are ASN and originated prefix
      $asn = 'AS'.$m[1];
      $prefix = $m[2];

      // Specific type requested ?
      if(!empty($type)) {
        switch($type) {
          case 'route':
            if(!is_ipv4($prefix))
              unset($prefix);
            break;
          case 'route6':
            if(!is_ipv6($prefix))
              unset($prefix);
            break;
          default:
            return;
        }
      }

      if(!empty($prefix))
        // Store extracted prefix
        $prefixes[$asn][] = $prefix;
    }

  }

  return $prefixes;
}

function query_whois($query, $type=NULL, $attr=NULL)
{
  global $config;

  // Don't waste my time ...
  if(empty($query))
    return;

  // Connect to RIPE RIS server
  $sock = whois_connect($config['whois_server']);
  if(!isset($sock))
    return;

  // Leave out contact info
  // to avoid daily limit ban:
  //
  //   http://www.ripe.net/data-tools/db/faq/faq-db/why-did-you-receive-the-error-201-access-denied
  //
  $command = "-r";
  // Preferred object type
  if(!empty($type))
    $command .= " -T".$type;
  // Inverse lookup by this attribute
  if(!empty($attr))
    $command .= " -i".$attr;
  // Append query string
  // and finalize command
  $command .= " ".$query."\n";

  // Query RIS server
  // -k   request persistant connection for bulk queries
  // -F   request short format response
  $response = whois_request($sock, $command);
  if(empty($response))
    return;

  $objects = array();
  $attr = NULL;
  $value = NULL;

  // Parse raw output
  foreach(explode("\n", $response) as $line) {

    // Skip comments
    if(preg_match('/^\s*%/', $line))
      continue;

    // Object ends with an empty line
    if(empty($line)) {
      unset($object_key);
      continue;
    }

    // Looking for "attribute: value" line
    if(preg_match('/^\s*([^\s:]+):\s*(.*)/i', $line, $m)) {

      // Matching data are attribute name and it's value
      $attr = $m[1];
      $value = $m[2];
      // If specific attribute was requested ...
      if(isset($type)) {
        // ... and we found it in the current line,
        // use it as the key in the array of results
        if($attr == $type)
          $object_key = $value;
      // Otherwise, if no specific attributes were requested ...
      } else {
        // ... use the first attribute we come across as key
        if(!isset($object_key))
          $object_key = $value;
      }
      // Store RPSL object
      if(isset($object_key)) {
        // If attribute already exists ...
        if(isset($objects[$object_key][$attr])) {
          // ... and is already an array ...
          if(is_array($objects[$object_key][$attr]))
            // ... add value along with others
            $objects[$object_key][$attr][] = $value;
          // Otherwise, convert it to array ...
          else
            // ... which will hold previous and current value
            $objects[$object_key][$attr] = array($objects[$object_key][$attr], $value);
        // If attribute doesn't exist, create it
        } else
          $objects[$object_key][$attr] = $value;
      }

    // Line is a continuation of prefious line(s) ?
    } elseif(preg_match('/^\s*(.+)/i', $line, $m)) {

      // Match should be a part of multiline value
      $value = $m[1];
      // Store RPSL object
      if(isset($object_key)) {
        // If attribute is an array ...
        if(is_array($objects[$object_key][$attr])) {
          $last = count($objects[$object_key][$attr]) - 1;
          // ... append to the last stored value
          $objects[$object_key][$attr][$last] .= $value;
        // Otherwise, if attribute holds a single value ...
        } else
          // ... simply append to it
          $objects[$object_key][$attr] .= $value;
      }

    }

  }

  return $objects;
}

// ************************** RPSL OBJECT FUNCTIONS ***************************

function aut_num($asn)
{
  // Uppercase the ASN
  $asn = strtoupper($asn);

  // Fetch AS data
  $object = query_whois($asn, 'aut-num');
  if(!is_array($object) || count($object) == 0 ||
     !is_array($object[$asn]) || count($object[$asn]) == 0)
    return;

  // Uppercase found object keys
  $object = array_change_key_case($object, CASE_UPPER);

  // Copy basic aut-num object attributes
  // (only the important ones)
  $aut_num = array(
    'aut-num' => $asn,
    'as-name' => strtoupper($object[$asn]['as-name'])
  );

  // Copy import attribute(s)
  if(isset($object[$asn]['import'])) {
    $imports = is_array($object[$asn]['import']) ?
                  $object[$asn]['import']:
                  array($object[$asn]['import']);
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
  if(isset($object[$asn]['export'])) {
    $exports = is_array($object[$asn]['export']) ?
                  $object[$asn]['export']:
                  array($object[$asn]['export']);
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
  if(isset($object[$asn]['mp-import'])) {
    $imports = is_array($object[$asn]['mp-import']) ?
                  $object[$asn]['mp-import']:
                  array($object[$asn]['mp-import']);
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
  if(isset($object[$asn]['mp-export'])) {
    $exports = is_array($object[$asn]['mp-export']) ?
                  $object[$asn]['mp-export']:
                  array($object[$asn]['mp-export']);
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

function as_set($as_set_name, &$members=array(), &$expanded=array())
{
  // Uppercase the AS set name
  $as_set_name = strtoupper($as_set_name);

  // If already expanded, abort
  if(isset($expanded[$as_set_name]))
    return;

  // Set ourselves as expanded to prevent
  // AS-set loops when called recursively
  $expanded[$as_set_name] = true;

  // Fetch AS set data
  $object = query_whois($as_set_name, 'as-set');
  if(!isset($object) || !is_array($object))
    return;

  // Uppercase found object's keys
  $object = array_change_key_case($object, CASE_UPPER);

  // Proper AS set object must have members attribute
  if(!isset($object[$as_set_name]) ||
     !isset($object[$as_set_name]['members']))
    return;

  // Store basic as-set object attributes
  // (only the important ones)
  $as_set = array('as-set' => $as_set_name);

  // Make sure we will be iterating
  // over array of unique members
  $raw_members = is_array($object[$as_set_name]['members']) ?
                   array_unique($object[$as_set_name]['members']):
                   array($object[$as_set_name]['members']);

  // Recursively copy and expand member attributes
  foreach($raw_members as $member) {
    // Skip parsing errors
    if(empty($member))
      continue;
    // String might contain comma-separated AS list
    foreach(preg_split('/[,;:]/', strtoupper($member)) as $member) {
      // Strip leading and trailing trash
      if(!preg_match('/([^\s#]+)/', $member, $m))
        continue;
      $member = $m[1];
      // If member is a simple ASN ...
//      if(preg_match('/(AS\d+)/i', $member, $m))
      if(is_asn($member))
        // ... just store it along with the rest
//        $members[$m[1]] = $m[1];
        $members[$member] = $member;
      // Otherwise, member should be an as-set ...
      else
        // Try to expand it
        as_set($member, $members, $expanded);
    }
  }

  // Store expanded members array
  $as_set['members'] = $members;

  return $as_set;
}

function route_set($route_set_name, &$members=array(), &$expanded=array())
{
  // Uppercase the route set name
  $route_set_name = strtoupper($route_set_name);

  // If already expanded, abort
  if(isset($expanded[$route_set_name]))
    return;

  // Set ourselves as expanded to prevent
  // route-set loops when called recursively
  $expanded[$route_set_name] = true;

  // Fetch route set data
  $object = query_whois($route_set_name, 'route-set');
  if(!isset($object) || !is_array($object))
    return;

  // Uppercase found object's keys
  $object = array_change_key_case($object, CASE_UPPER);

  // Proper route-set object must have members attribute
  if(!isset($object[$route_set_name]) ||
     !isset($object[$route_set_name]['members']))
    return;

  // Store basic route-set object attributes
  // (only the important ones)
  $route_set = array('route-set' => $route_set_name);

  // Make sure we will be iterating over array of unique members
  $raw_members = is_array($object[$route_set_name]['members']) ?
                   array_unique($object[$route_set_name]['members']):
                   array($object[$route_set_name]['members']);

  // Recursively copy and expand member attributes
  foreach($raw_members as $member) {
    // Skip parsing errors
    if(empty($member))
      continue;
    // String might contain comma-separated list of members
    foreach(preg_split('/(?:\^[^,\s]*)?\s*[,\s]\s*/', strtoupper($member)) as $member) {
      // Strip leading and trailing trash
      if(!preg_match('/([^\s#]+)/', $member, $m))
        continue;
      $member = $m[1];
      // If member is an IPv4 prefix ...
      if(is_ipv4($member))
        // ... just store it along with the rest
        $members[$member] = $member;
      // Otherwise, member should be a route-set ...
      else
        // Try to expand it
        route_set($member, $members, $expanded);
    }
  }

  // Store expanded members array
  $route_set['members'] = $members;

  return $route_set;
}

function route6_set($route_set_name, &$members=array(), &$expanded=array())
{
  // Uppercase the route set name
  $route_set_name = strtoupper($route_set_name);

  // If already expanded, abort
  if(isset($expanded[$route_set_name]))
    return;

  // Set ourselves as expanded to prevent
  // route-set loops when called recursively
  $expanded[$route_set_name] = true;

  // Fetch route set data
  $object = query_whois($route_set_name, 'route-set');
  if(!isset($object) || !is_array($object))
    return;

  // Uppercase found object's keys
  $object = array_change_key_case($object, CASE_UPPER);

  // Proper route-set object must have mp-members attribute
  if(!isset($object[$route_set_name]) ||
     !isset($object[$route_set_name]['mp-members']))
    return;

  // Store basic route-set object attributes
  // (only the important ones)
  $route_set = array('route-set' => $route_set_name);

  // Make sure we will be iterating over array of unique mp-members
  $raw_members = is_array($object[$route_set_name]['mp-members']) ?
                   array_unique($object[$route_set_name]['mp-members']):
                   array($object[$route_set_name]['mp-members']);

  // Recursively copy and expand member attributes
  foreach($raw_members as $member) {
    // Skip parsing errors
    if(empty($member))
      continue;
    // String might contain comma-separated list of members
    foreach(preg_split('/(?:\^[^,\s]*)?\s*[,\s]\s*/', strtoupper($member)) as $member) {
      // Strip leading and trailing trash
      if(!preg_match('/([^\s#]+)/', $member, $m))
        continue;
      $member = $m[1];
      // If member is an IPv6 prefix ...
      if(is_ipv6($member))
        // ... just store it along with the rest
        $members[$member] = $member;
      // Otherwise, member should be a route-set ...
      else
        // Try to expand it
        route6_set($member, $members, $expanded);
    }
  }

  // Store expanded members array
  $route_set['mp-members'] = $members;

  return $route_set;
}

// ***************************** PREFIX FUNCTIONS *****************************

function get_ipv4_prefixes_by_origin($asn)
{
  // Fetch route objects originated by this AS
  $object = query_whois($asn, 'route', 'origin');
  if(!isset($object) ||
     !is_array($object) ||
     count($object) == 0)
    return;

  return array_keys($object);
}

function get_ipv6_prefixes_by_origin($asn)
{
  // Fetch route objects originated by this AS
  $object = query_whois($asn, 'route6', 'origin');
  if(!isset($object) ||
     !is_array($object) ||
     count($object) == 0)
    return;

  return array_keys($object);
}

function get_ipv4_prefix_origin($prefix)
{
  // Fetch route object for these prefix
  $object = query_whois($prefix, 'route');
  if(!isset($object) ||
     !is_array($object) ||
     !isset($object[$prefix]) ||
     !is_array($object[$prefix]) ||
     empty($object[$prefix]['origin']))
    return;

  return $object[$prefix]['origin'];
}

function get_ipv6_prefix_origin($prefix)
{
  // Fetch route6 object for these prefix
  $object = query_whois($prefix, 'route6');
  if(!isset($object) ||
     !is_array($object) ||
     !isset($object[$prefix]) ||
     !is_array($object[$prefix]) ||
     empty($object[$prefix]['origin']))
    return;

  return $object[$prefix]['origin'];
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
      $exported = array_keys($as_set['members']);
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route_set = route_set($exported);
    if(isset($route_set) && is_array($route_set))
      $exported = array_keys($route_set['members']);
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
      $exported = array_keys($as_set['members']);
  // If exporting route-set ...
  } elseif(preg_match('/^RS\-/i', $exported)) {
    // ... expand it into a full list of prefixes
    $route_set = route6_set($exported);
    if(isset($route_set) && is_array($route_set))
      $exported = array_keys($route_set['mp-members']);
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

  // If array elements are IPv4 prefixes ...
  if(is_ipv4($exported)) {

    // ... we got inline list of prefixes
    foreach($exported as $prefix) {
      // Resolve prefix origin
      // (slow with large number of prefixes)
      $asn = get_ipv4_prefix_origin($prefix);
      // Store prefix into announced list
      if(!empty($asn))
        $announced[$asn][] = $prefix;
    }

  // Otherwise, if not IPv6 prefixes
  // (which would surely be a mistake) ...
  } elseif(!is_ipv6($exported)) {

    // Use RIS server to fetch prefixes ?
    if(isset($config['use_ris']) &&
       $config['use_ris'] === TRUE)
      return query_ris($exported, 'route');

    // Use Whois to fetch prefixes by default

    // Request prefixes for every ASN in the list
    // (slow but more reliable than RIS)
    foreach($exported as $asn) {
      // Skip target ASN if found among exported ASNs.
      // No point exporting it to itself.
      if($asn == $to_asn)
        continue;
      $prefixes = get_ipv4_prefixes_by_origin($asn);
      // Store prefixes into announced list
      if(isset($prefixes))
        $announced[$asn] = $prefixes;
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

  // If array elements are IPv6 prefixes ...
  if(is_ipv6($exported)) {

    // ... we got inline list of announced prefixes
    foreach($exported as $prefix) {
      // Resolve prefix origin
      // (slow with large number of prefixes)
      $asn = get_ipv6_prefix_origin($prefix);
      // Store prefix into announced list
      if(!empty($asn))
        $announced[$asn][] = $prefix;
    }

  // Otherwise, if not IPv4 prefixes
  // (which would surely be a mistake) ...
  } elseif(!is_ipv4($exported)) {

    // Use RIS server to fetch prefixes ?
    if(isset($config['use_ris']) &&
       $config['use_ris'] === TRUE)
      return query_ris($exported, 'route6');

    // Use Whois to fetch prefixes by default

    // Request prefixes for every ASN in the list
    // (slow but more reliable than RIS)
    foreach($exported as $asn) {
      // Skip target ASN if found among exported ASNs.
      // No point exporting it to itself.
      if($asn == $to_asn)
        continue;
      $prefixes = get_ipv6_prefixes_by_origin($asn);
      // Store prefixes into announced list
      if(isset($prefixes))
        $announced[$asn] = $prefixes;
    }

  }

  return $announced;
}

?>
