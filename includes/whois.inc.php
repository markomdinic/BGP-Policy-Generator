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

// **************************** RPSL PREPROCESSOR *****************************

function merge_policies($policies1=array(), $policies2=array())
{
  // Merge policies2 ...
  foreach(array_keys($policies2) as $af) {
    // ... with policies1 by adding
    // policies2 to policies1
    foreach($policies2[$af] as $peer => &$filter) {
      $policies1[$af][$peer] = (isset($policies1[$af][$peer]) &&
                                !empty($policies1[$af][$peer])) ?
                                  "( ".$policies1[$af][$peer]." ) OR ( ".$filter." )":
                                  $filter;
    }
  }
  // Return resulting policies
  return $policies1;
}

function add_policy($policies, $family, $peer, $filter)
{
  // For every specified address family ...
  foreach($family as $af) {
    // ... add or append new policy
    $policies[$af][$peer] = (isset($policies[$af][$peer]) &&
                             !empty($policies[$af][$peer])) ?
                               "( ".$policies[$af][$peer]." ) OR ( ".$filter." )":
                               $filter;
  }
  // Return resulting policies
  return $policies;
}

function preprocess_policy($term=NULL, $family=array(AF_INET), &$tokens=NULL, $begin=NULL)
{
  // Either policy term or begin+tokens have to be defined
  if(empty($term) && empty($tokens))
    return false;

  if(is_string($term)) {
    debug_message('preprocessor', "Input term: \"".$term."\"");
    // Look for sub-terms
    if(preg_match_all('/([\{\};]|[^,\s\{\};]+)/', strtolower($term), $tokenized))
      // Tokenize term
      $tokens = array_shift($tokenized);
  }

  if(empty($tokens))
    return;

  debug_message('preprocessor', "Term tokens:", $tokens);

  // Start with an empty result set
  $result = array();

  // Parse tokens
  while(!empty($tokens)) {

    // Get next token
    $token = array_shift($tokens);
    if(empty($token))
      break;

    // Detect what this token is
    switch($token) {
      // Operators
      case 'afi':
        $operator = empty($operator) ?
                      $token:$operator.$token;
        break;
      case 'protocol':
      case 'from':
      case 'to':
      case 'accept':
      case 'announce':
      case 'except':
      case 'refine':
        // Another operation already in progress ?
        if(!empty($operator))
          return false;
        // If cumulative result is a simple list,
        // no operators can be used within
        if(is_sequential_array($result))
          return false;
        $operator = $token;
        break;
      // End operation
      case ';':
        if(empty($operator))
          break;
        // Only certain operations are handled
        switch($operator) {
          case 'accept':
          case 'announce':
            unset($proto, $operator, $peer);
            $family = array(AF_INET);
            break;
        }
        break;
      // Begin term
      case '{':
        // Parse sub-term
        $subterm = preprocess_policy(NULL,
                                     $family,
                                     $tokens,
                                     $token);
        // If failed to parse term ...
        if($subterm === FALSE)
          // ... propagate error state up
          return false;
        // Generic term or a simple list ?
        if(empty($operator)) {
          // Simple lists of operands of
          // unhandled operation types
          // should be discarded
          if(is_sequential_array($subterm))
            break;
          // Add sub-term results to our own
          $result = merge_policies($result, $subterm);
          break;
        }
        // Determine what to do with expanded term
        // based on the type of operation that is
        // in progress
        switch($operator) {
          // ACCEPT operator ?
          case 'accept':
          // ANNOUNCE operator ?
          case 'announce':
            if(empty($peer))
              return false;
            // Term is a simple list of operands.
            // Format policy filter by ORing
            // operands together
            $result = add_policy($result,
                                 $family,
                                 $peer,
                                 "{ ".implode(' ', $subterm)." }");
            break;
          // EXCEPT operator ?
          case 'except':
            foreach($family as $af) {
              // The following code implements EXCEPT
              // operator the way RFC2622 defines it
              foreach($result[$af] as $l => &$lefthand_filter) {
                // Make a copy of yet unmodified lefthand filters.
                $unmodified_lefthand_filter = $lefthand_filter;
                // RFC2622 says lefthand side filters are modified
                // to exclude routes matched by the righthand side.
                $lefthand_filter .= " AND NOT (".implode(" OR ", $subterm[$af]).")";
                foreach($subterm[$af] as $r => &$righthand_filter) {
                  // RFC2622 says righthand side filters are modified
                  // to include routes matched by both sides of EXCEPT
                  // operator.
                  $righthand_filter = $unmodified_lefthand_filter." AND ".$righthand_filter;
                  // Merge left and right side
                  $result[$af][$r] = isset($result[$af][$r]) ?
                                        "(".$result[$af][$r].") OR (".$righthand_filter.")":
                                        $righthand_filter;
                }
              }
            }
            break;
          // REFINE operator ?
          case 'refine':
            $policy = array();
            foreach($family as $af) {
              // RFC2622 says the resulting set is constructed
              // by taking the cartasian product of two sides
              // as follows:
              foreach($result[$af] as $l => &$lefthand_filter) {
                if(empty($l) || empty($lefthand_filter))
                  continue;
                // For each policy l in the left hand side ...
                foreach($subterm[$af] as $r => &$righthand_filter) {
                  if(empty($r) || empty($righthand_filter))
                    continue;
                  // ... the peerings of the resulting policy
                  // are the peerings common to both r and l
                  $common = array($l, $r); sort($common);
                  $peerings = ($l != $r) ?
                                "(".implode(" AND ", $common).")":
                                $l;
                  // The filter of the resulting policy is
                  // the intersection of l's filter and r's
                  // filter
                  $filter = ($lefthand_filter != $righthand_filter) ?
                              "(".$lefthand_filter." AND ".$righthand_filter.")":
                              $lefthand_filter;
                  // Put together resulting policy
                  $policy[$af][$peerings] = isset($policy[$af][$peerings]) ?
                                              "(".$policy[$af][$peerings].") OR (".$filter.")":
                                              $filter;
                }
              }
            }
            // If there are no common peerings, or if
            // the intersection of filters is empty,
            // a resulting policy is not generated.
            if(!empty($policy))
              $result = $policy;
            break;
        }
        unset($operator);
        break;
      // End term
      case '}':
        // Closing brace must match
        // the type of opening one
        if($begin != '{')
          return false;
        // Return our result set immediately
        return $result;
      // NOOP
      case ',':
        break;
      // Single operand
      default:
        // If operator isn't set ...
        if(empty($operator)) {
          // ... and peer is unknown,
          // we are not inside any
          // policy term, therefore ...
          if(!empty($peer))
            break;
          // ... tokens are a simple list elements,
          // and the result itself is a simple list
          $result[] = $token;
          continue;
        }
        // Determine what to do with operand
        // based on the operation in progress
        switch($operator) {
          case 'afi':
          case 'exceptafi':
          case 'refineafi':
            // Determine the address family
            switch($token) {
              case 'ipv4.unicast':
              case 'ipv4.multicast':
              case 'ipv4':
                $family = array(AF_INET);
                break;
              case 'ipv6.unicast':
              case 'ipv6.multicast':
              case 'ipv6':
                $family = array(AF_INET6);
                break;
              case 'any.unicast':
              case 'any.multicast':
              case 'any':
                $family = array(AF_INET, AF_INET6);
                break;
              default:
                return false;
            }
            $operator = substr($operator, 0, -3);
            if(empty($operator))
              unset($operator);
            break;
          case 'protocol':
            $proto = $token;
            unset($operator);
            break;
          case 'from':
          case 'to':
            $peer = strtoupper($token);
            unset($operator);
            break;
          case 'accept':
          case 'announce':
            // At this point peer must be defined
            if(empty($peer))
              return false;
            // If protocol was specified,
            // but it is not BGP, ignore
            if(!empty($proto) && !in_array($proto, array('bgp4','bgp'))) {
              unset($proto, $operator, $peer);
              $family = array(AF_INET);
              break;
            }
            // Add policy to the result
            $result = add_policy($result,
                                 $family,
                                 $peer, 
                                 strtoupper($token));
            break;
          default:
            return false;
        }
        break;
    }

  }

  debug_message('preprocessor', "Term \"".$term."\" expands to:", $result);

  // Policy is done
  return $result;
}


// ***************** LOW LEVEL RPSL OBJECT PARSING FUNCTIONS ******************

function parse_aut_num($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to aut-num parser.");
    return;
  }

  if(!isset($object['aut-num']) || empty($object['aut-num'])) {
    debug_message('parser', "Raw object passed to aut-num parser is missing primary key.");
    return;
  }

  if(!(isset($object['import']) || isset($object['mp-import']))) {
    debug_message('parser', "Raw object ".$object['aut-num']." passed to aut-num parser is missing import attributes.");
    return;
  }

  if(!(isset($object['export']) || isset($object['mp-export']))) {
    debug_message('parser', "Raw object ".$object['aut-num']." passed to aut-num parser is missing export attributes.");
    return;
  }

  // Begin constructing new aut-num object
  $aut_num = array();

  // Parse import policies
  if(isset($object['import']))
    $imports = is_array($object['import']) ?
                 $object['import']:
                 array($object['import']);

  // Parse multiprotocol import policies
  if(isset($object['mp-import']))
    $imports = array_merge(empty($imports) ? array():$imports,
                           is_array($object['mp-import']) ?
                             $object['mp-import']:
                             array($object['mp-import']));

  if(!empty($imports))
    // Pass each policy through preprocessor, then merge results
    $aut_num['import'] = array_reduce(array_map('preprocess_policy', $imports), 'merge_policies');

  // Parse export policies
  if(isset($object['export']))
    $exports = is_array($object['export']) ?
                 $object['export']:
                 array($object['export']);

  // Parse multiprotocol export policies
  if(isset($object['mp-export']))
    $exports = array_merge(empty($exports) ? array():$exports,
                           is_array($object['mp-export']) ?
                             $object['mp-export']:
                             array($object['mp-export']));

  if(!empty($exports))
    // Pass each policy through preprocessor, then merge results
    $aut_num['export'] = array_reduce(array_map('preprocess_policy', $exports), 'merge_policies');

  // Object is not complete ?
  if(empty($aut_num)) {
    debug_message('parser', "aut-num parser failed to parse raw object ".$object['aut-num'].".");
    return;
  }

  if(!isset($aut_num['import'])) {
    debug_message('parser', "Parsed aut-num object ".$object['aut-num']." is missing import attributes.");
    return;
  }

  if(!isset($aut_num['export'])) {
    debug_message('parser', "Parsed aut-num object ".$object['aut-num']." is missing export attributes.");
    return;
  }

  // Add the rest of attributes of interest
  $aut_num['aut-num'] = strtoupper($object['aut-num']);

  // Done
  return $aut_num;
}

function parse_as_set($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to as-set parser.");
    return;
  }

  if(!isset($object['as-set']) || empty($object['as-set'])) {
    debug_message('parser', "Raw object passed to as-set parser is missing primary key.");
    return;
  }

  if(!isset($object['members']) || empty($object['members'])) {
    debug_message('parser', "Raw object ".$object['as-set']." passed to as-set parser is missing members attribute.");
    return;
  }

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
      $member = trim($member);
      // Store parsed member
      if(!empty($member))
        // By storing members as array keys
        // we eliminate duplicate entries
        $parsed_members[$member] = true;
    }
  }

  if(empty($parsed_members)) {
    debug_message('parser', "Parsed as-set object ".$object['as-set']." is missing members.");
    return;
  }

  // Format and return final object
  return array(
    'as-set' => strtoupper($object['as-set']),
    'members' => array_keys($parsed_members)
  );
}

function parse_route_set($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to route-set parser.");
    return;
  }

  if(!isset($object['route-set']) || empty($object['route-set'])) {
    debug_message('parser', "Raw object passed to route-set parser is missing primary key.");
    return;
  }

  if(!isset($object['members']) || empty($object['members'])) {
    debug_message('parser', "Raw object ".$object['route-set']." passed to route-set parser is missing members attribute.");
    return;
  }

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
      $member = trim($member);
      // Store parsed member
      if(!empty($member))
        // By storing members as array keys
        // we eliminate duplicate entries
        $parsed_members[$member] = true;
    }
  }

  if(empty($parsed_members)) {
    debug_message('parser', "Parsed route-set object ".$object['route-set']." is missing members.");
    return;
  }

  // Format and return final object
  return array(
    'route-set' => strtoupper($object['route-set']),
    'members' => array_keys($parsed_members)
  );
}

function parse_filter_set($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to filter-set parser.");
    return;
  }

  if(!isset($object['filter-set'])) {
    debug_message('parser', "Raw object passed to route-set parser is missing primary key.");
    return;
  }

  if(!isset($object['filter'])) {
    debug_message('parser', "Raw object ".$object['filter-set']." passed to route-set parser is missing filter expression.");
    return;
  }

  // Format and return final object
  return array(
    'filter-set' => strtoupper($object['filter-set']),
    'filter' => strtoupper($object['filter'])
  );
}

function parse_route($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to route parser.");
    return;
  }

  if(!isset($object['route']) || empty($object['route'])) {
    debug_message('parser', "Raw object passed to route parser is missing primary key.");
    return;
  }

  if(!isset($object['origin']) || empty($object['origin'])) {
    debug_message('parser', "Raw object ".$object['route']." passed to route parser is missing origin attribute.");
    return;
  }

  return array(
    'route' => $object['route'],
    'origin' => strtoupper($object['origin'])
  );
}

function parse_route6($object)
{
  // Don't waste time ...
  if(empty($object)) {
    debug_message('parser', "Empty raw object passed to route6 parser.");
    return;
  }

  if(!isset($object['route6']) || empty($object['route6'])) {
    debug_message('parser', "Raw object passed to route6 parser is missing primary key.");
    return;
  }

  if(!isset($object['origin']) || empty($object['origin'])) {
    debug_message('parser', "Raw object ".$object['route6']." passed to route6 parser is missing origin attribute.");
    return;
  }

  return array(
    'route' => strtolower($object['route']),
    'origin' => strtoupper($object['origin'])
  );
}

// ************************ LOW LEVEL WHOIS FUNCTIONS *************************

function whois_query_server($server, $search_list, $object_type=NULL, $inverse_lookup_attr=NULL, &$cache=NULL)
{
  // If search list is empty ...
  if(empty($search_list))
    // ... return an empty result
    return;

  // Make sure search list is always an array
  // even if it contains a single element
  if(!is_array($search_list))
    $search_list = array($search_list);

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
    debug_message('transport', "Whois server address ".$host." not found in cache.");
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
              debug_message('transport', "Caching resolved server address ".$host." to ".$record['ip'].".");
              break;
            case 'AAAA':
              $addrs[$host][AF_INET6] = $record['ipv6'];
              debug_message('transport', "Caching resolved server address ".$host." to ".$record['ipv6'].".");
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
        debug_message('info', "Invalid address family \"".trim($af)."\". Check your configuration ?");
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
      debug_message('info', "Using RIPE-compatibile bulk query mode.");
      break;
    // Whois server is based on IRRd software.
    // It's compatibile with RIPE for the most
    // part, but persistant connection mode is
    // handled slightly differently
    case 'irrd':
      // Enable bulk mode
      $begin = "!!\n";
      $end = "q\n";
      debug_message('info', "Using irrd-compatibile bulk query mode.");
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
      debug_message('info', "Using normal query mode.");
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
  for($prepared = 0, $num_obj = sizeof($search_list); $prepared < $num_obj; $prepared += $query_size)
    // Prepare a query of query_size number of objects.
    $queries[] = $begin.$options." ".implode("\n".$options." ", array_slice($search_list, $prepared, $query_size))."\n".$end;

  debug_message('info', "Querying server ".$host." ...");

  // Found, fully assembled objects go here
  $objects = array();

  // List of objects not found by the search
  // starts from the full search list and
  // gets trimmed down with each found object
  $missing = array_flip($search_list);

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
          // Otherwise ...
          $errno = socket_last_error($sock);
          // ... if error is something other than
          // "Operation already in progress" ...
          if(!in_array($errno, array(0, EALREADY, EINPROGRESS))) {
            debug_message('transport', "Failed to connect to server ".$host.": ".socket_strerror($errno));
            // ... abort current connect operation
            // and try the next address family
            break;
          }
          // If a connect operation is in progress,
          // wait a bit and then go back to check
          // for status, until operation is complete
          // or we break the connect deadline
          sleep(0.001);
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

    // Prepare query size counter
    $total_sent = 0;

    // Send whois query
    for($sent = 0, $query_length = strlen($query);
        $total_sent < $query_length;
        $total_sent += $sent) {

      // Query timeout ?
      if(time() > $query_deadline) {
        debug_message('info', "Query timed out.");
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
      $sent = @socket_send($sock, substr($query, $total_sent), $query_length - $total_sent, 0);

      // Error ?
      if($sent === FALSE) {
        socket_close($sock);
        return false;
      }

      debug_message('transport', "Sent ".$sent." bytes of whois query.");
    }

    debug_message('transport', "Delivered whois query in full, total of ".$total_sent." bytes.");

    // Prepare object parsing variables
    $object = NULL;
    $type = NULL;
    $key = NULL;
    $attr = NULL;
    $value = NULL;
    $skip = false;

    // Raise our receive & parse flag
    $receive = true;

    // Prepare response size counter
    $total_received = 0;

    // Prepare response data storage
    $response = "";

    // Read and parse whois response
    while($receive) {

      // Query timeout ?
      if(time() > $query_deadline) {
        debug_message('info', "Query timed out.");
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
      if($num_ready == 0) {
        debug_message('transport', "Socket is idle.");
        continue;
      }

      // Socket is ready, there's has data to be read
      debug_message('transport', "Socket is ready for reading. Receiving response from server.");

      // Drain the socket
      while($receive) {

        // Get a part of response
        $received = @socket_recv($sock, $buffer, 1000000, MSG_WAITALL);

        // Read failed ?
        if($received === FALSE) {
          // What exactly happened ?
          $errno = socket_last_error($sock);
          switch($errno) {
            // Nothing to read at the moment ...
            case EWOULDBLOCK:
              break 2;
            // Connection closed ...
            case ECONNRESET:
              debug_message('transport', "Server closed the connection.");
              break;
            default:
              // Otherwise it is an error
              socket_close($sock);
              debug_message('transport', "Socket error: ".socket_strerror($errno));
              return false;
          }
        }

        // If we recived data ...
        if($received > 0) {
          // ... append it to the rest of response data
          $response .= $buffer;
          // ... count total bytes received
          $total_received += $received;
          debug_message('transport', "Received ".$received." bytes of whois response.");
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
            debug_message('parser', "-------------- EMPTY LINE --------------");
            // If object type and raw object data exist ...
            if(!empty($type) && !empty($object)) {
              debug_message('parser', $type." object ".$key." assembled raw ...");
              // ... look for parser for that particular object type
              $parser = 'parse_'.str_replace('-', '_', $type);
              // If parser exists ...
              if(function_exists($parser)) {
                debug_message('parser', "Passing raw ".$type." object ".$key." to type-specific parser ...");
                // ... invoke it to replace raw object
                // with a more refined, parsed form
                $object = call_user_func($parser, $object);
              }
            }
            // Each entry in the array of objects represents
            // a single object. However, if searching multiple
            // sources, each entry can be an array of different
            // versions of the same object provided by different
            // sources in the same order sources were searched.
            // Sources are searched in descending order of
            // significance, thus we will simply pick the first
            // (most significant) version of an object and ignore
            // the rest
            if(!empty($key) && !empty($object)) {
              if(!isset($objects[$key])) {
                $objects[$key] = $object;
                debug_message('parser', "New ".$type." object ".$key." complete.");

                // Result caching enabled ?
                if(isset($cache)) {

                  // Direct lookup ?
                  if(empty($inverse_lookup_attr)) {

                    // Cache direct search results and
                    // negative cache missing objects
                    $cache['direct'][$key] = $object;
                    debug_message('cache', "Caching direct query result: ".$key);
                    // Remove object from the list of missing objects
                    unset($missing[$key]);

                  // Inverse lookup
                  } elseif(isset($object[$inverse_lookup_attr])) {

                    // Cache object under inverse index
                    $cache['inverse'][$inverse_lookup_attr][$object[$inverse_lookup_attr]][$key] = $object;
                    debug_message('cache', "Caching object ".$key." from inverse query ".$inverse_lookup_attr." = ".$object[$inverse_lookup_attr]);
                    // Remove object from the list of missing objects
                    unset($missing[$object[$inverse_lookup_attr]]);

                  } else
                    debug_message('cache', "Object ".$key." from inverse query by ".$inverse_lookup_attr." is missing inverse lookup attribute ".$inverse_lookup_attr.".");

                }

              } else
                debug_message('parser', "Discarding duplicate ".$type." object ".$key.".");
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
          if(preg_match('/^([^\s:]+):\s*(.*?)(?:#.*)?$/', $line, $m)) {
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
              case 'filter-set':
              case 'filter':
                $value = $m[2];
                break;
              // Skip attributes we don't need
              default:
                debug_message('parser', "Discarding unneeded attribute ".$attr.".");
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
                debug_message('parser', "Skipping filtered ".$attr." object ".$value." (using only ".$object_type." objects).");
                continue;
              }
              // If object with the same primary key already exists ...
              if(isset($objects[$value])) {
                // ... skip source lines until the next object
                $skip = true;
                debug_message('parser', "Ignoring duplicate ".$attr." object ".$value.".");
                continue;
              }
              // Otherwise, begin constructing a new object
              // and remember object's type and primary key
              $object = array();
              $type = $attr;
              $key = $value;
              debug_message('parser', "Assembling new ".$type." object ".$key." ...");
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
                  $object[$attr][$last] .= ' '.$value;
              // Otherwise, if attribute holds a single value ...
              } else
                // ... simply append to it
                $object[$attr] .= ' '.$value;
            }

          }

        }

      }

    }

    debug_message('transport', "Received whois response in full, total of ".$total_received." bytes.");

    // Close connection
    socket_close($sock);
    $sock = false;

  }

  // Result caching enabled ?
  if(isset($cache)) {
    // Direct lookup ?
    if(empty($inverse_lookup_attr)) {
      // Negative cache objects not found by direct query
      $cache['direct'] = array_merge($cache['direct'], $missing);
      if(!empty($missing))
        debug_message('cache', "Negative caching direct query results: [", array_keys($missing), "].");
    } else {
      // Negative cache objects not found by inverse query
      $cache['inverse'][$inverse_lookup_attr] = array_merge($cache['inverse'][$inverse_lookup_attr], $missing);
      if(!empty($missing))
        debug_message('cache', "Negative caching results from inverse query by ".$inverse_lookup_attr.": [", array_keys($missing), "].");
    }
  }

  // At this point, all queries have been executed
  return $objects;
}

function whois_query($search_list, $object_type=NULL, $inverse_lookup_attr=NULL, &$servers=NULL)
{
  global $config;
  static $cache;

  // Don't waste time ...
  if(empty($search_list))
    return;

  // Make sure this is always a list
  if(!is_array($search_list))
    $search_list = array($search_list);

  // Initialize the cache on the first run
  if(!isset($cache))
    $cache = array('direct' => array(), 'inverse' => array());

  $cache_hits = array();

  // Direct lookup ?
  if(!isset($inverse_lookup_attr)) {

    // Search objects in cache by primary key
    $cache_hits = array_intersect_key($cache['direct'], array_flip($search_list));

    if(count($cache_hits) > 0) {
      debug_message('cache', "Direct query cache hits: [", array_keys($cache_hits), "]");
      $search_list = array_diff($search_list, array_keys($cache['direct']));
    }

  // Inverse lookup
  } elseif(isset($cache['inverse'][$inverse_lookup_attr])) {

    // Search objects in cache inversely, by given attribute
    $cache_hits = array_intersect_key($cache['inverse'][$inverse_lookup_attr], array_flip($search_list));

    if(count($cache_hits) > 0) {
      debug_message('cache', "Inverse query cache hits: [", array_keys($cache_hits), "]");
      $search_list = array_diff($search_list, array_keys($cache['inverse'][$inverse_lookup_attr]));
    }

  }

  // If all objects have been found in cache ...
  if(empty($search_list))
    // ... we are done
    return $cache_hits;

  // If Whois servers' weren't given ...
  if(empty($servers))
    // ... use globally configured ones
    $servers =& $config['whois'];

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
                                  $search_list,
                                  $object_type,
                                  $inverse_lookup_attr,
                                  $cache);
    // If query failed ...
    if($objects === false) {
      if(isset($servers[0]['server']) &&
         !empty($servers[0]['server']))
        debug_message('transport', "Removing failed server ".$servers[0]['server']." from the list.");
      else
        debug_message('transport', "Removing invalid server from the list. Check your configuration ?");
      // ... remove failed server from the list
      array_shift($servers);
      // ... try the next server
      continue;
    }

    // Return cache hits and search results combined
    return array_merge($cache_hits, $objects);
  }

  // If we reached this point,
  // we have nothing in cache
  // and no usable servers
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
     !is_rpsl_object($res[$asn]) ||
     !isset($res[$asn]['import']) ||
     !isset($res[$asn]['export']))
    return;

  return $res[$asn];
}

function route($prefix, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($prefix) || !is_ipv4($prefix))
    return;

  // Fetch route
  $res = whois_query($prefix,
                     'route',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$prefix]) ||
     !is_rpsl_object($res[$prefix]) ||
     !isset($res[$asn]['origin']));
    return;

  return $res[$prefix];
}

function route6($prefix, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($prefix) || !is_ipv6($prefix))
    return;

  // Fetch route
  $res = whois_query($prefix,
                     'route6',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$prefix]) ||
     !is_rpsl_object($res[$prefix]) ||
     !isset($res[$asn]['origin']));
    return;

  return $res[$prefix];
}

function as_set($as_set_name, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($as_set_name))
    return;

  // Uppercase the as-set name
  $as_set_name = strtoupper($as_set_name);

  // Fetch AS set
  $res = whois_query($as_set_name,
                     'as-set',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$as_set_name]) ||
     !is_rpsl_object($res[$as_set_name]) ||
     !isset($res[$asn]['members']));
    return;

  return $res[$as_set_name];
}

function route_set($route_set_name, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($route_set_name))
    return;

  // Uppercase the route-set name
  $route_set_name = strtoupper($route_set_name);

  // Fetch route set
  $res = whois_query($route_set_name,
                     'route-set',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$route_set_name]) ||
     !is_rpsl_object($res[$route_set_name]) ||
     !isset($res[$asn]['members']));
    return;

  return $res[$route_set_name];
}

function filter_set($filter_set_name, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($filter_set_name))
    return;

  // Uppercase the filter-set name
  $filter_set_name = strtoupper($filter_set_name);

  // Fetch route set
  $res = whois_query($filter_set_name,
                     'filter-set',
                     NULL,
                     $servers);

  if(empty($res) ||
     !is_array($res) ||
     !isset($res[$filter_set_name]) ||
     !is_rpsl_object($res[$filter_set_name]) ||
     !isset($res[$asn]['filter']));
    return;

  return $res[$filter_set_name];
}

// ***************************** POLICY FUNCTIONS *****************************

function expand_expression($filter=NULL, $family=AF_INET, $result_type=NULL, &$servers=NULL, &$tokens=NULL, $begin=NULL)
{
  // Either filter or begin+tokens have to be defined
  if(empty($filter) && empty($tokens))
    return false;

  if(is_string($filter)) {
    debug_message('expression', "Input expression: \"".$filter."\"");
    // Look for subexpressions
    if(preg_match_all('/([\<\(\{\}\)\>]|[^,\s\<\(\{\}\)\>]+)/', $filter, $tokenized))
      // Tokenize filter
      $tokens = array_shift($tokenized);
  }

  if(empty($tokens))
    return;

  debug_message('expression', "Expression tokens:", $tokens);

  switch($family) {
    case AF_INET:
      $route_type = 'route';
      $default_network = '0.0.0.0/0';
      break;
    case AF_INET6:
      $route_type = 'route6';
      $default_network = '::/0';
      break;
  }

  // Start with an empty result set
  $result = array();

  // This allows parser to skip
  // parts of expression up to
  // the specified delimiter
  $skip_until = NULL;
  $skipped = array();

  // Parse tokens
  while(!empty($tokens)) {

    // Get next token
    $token = array_shift($tokens);
    if(empty($token))
      break;

    // Ignore tokens until
    // delimiter is found
    if(!empty($skip_until) &&
       $token != $skip_until) {
      // Keep track of what was skipped
      $skipped[] = $token;
      continue;
    }

    // Detect what this token is
    switch($token) {
      // Skip as-path regex,
      // we can't apply it
      // in this context
      case '<':
        $skip_until = '>';
        break;
      // End as-path regex skipping
      case '>':
        debug_message('expression', "Ignoring inline AS path regex \"", $skipped, "\" part of expression in this context.");
        unset($skip_until, $skipped);
        break;
      // Begin subexpression
      case '{':
      case '(':
        // Parse subexpression
        $subexpr = expand_expression(NULL,
                                     $family,
                                     $result_type,
                                     $servers,
                                     $tokens,
                                     $token);
        // If failed to parse subexpression ...
        if($subexpr === FALSE)
          // ... propagate error state up
          return false;
        // If subexpression produced no results ...
        if(empty($subexpr))
          // ... do nothing
          break;
        //
        // Add subexpression results to
        // our result set, otherwise ...
        //
        // If operator isn't set, assume OR ...
        if(empty($operator))
          $operator = 'OR';
        // Apply operand to the result
        switch($operator) {
          case 'AND':
            $result = ($result_type & RPSL_OBJECTS) ?
                         array_intersect_key($result, $subexpr):
                         array_intersect($result, $subexpr);
            break;
          case 'OR':
            $result = array_merge($result, $subexpr);
            break;
          case 'EXCEPT':
          case 'ANDNOT':
            $result = ($result_type & RPSL_OBJECTS) ?
                         array_diff_key($result, $subexpr):
                         array_diff($result, $subexpr);
            break;
          default:
            return false;
        }
        // Clear operator
        unset($operator);
        break;
      // End subexpression
      case '}':
        // Closing brace must match
        // the type of the opening one
        if($begin != '{')
          return false;
        // Return our result set immediately
       return $result;
      case ')':
        // Closing brace must match
        // the type of the opening one
        if($begin != '(')
          return false;
        // Return our result set immediately
        return $result;
      // Logical operators
      case 'AND':
      case 'OR':
      case 'EXCEPT':
        // Operator is already set ...
        if(!empty($operator))
          // ... another one is clearly
          // a syntax error
          return false;
        $operator = $token;
        break;
      case 'NOT':
        // If operator is not already set ...
        if(empty($operator))
          // ... we have nothing to stick
          // NOT to, so for our purposes
          // we will treat it as error,
          // even though RPSL spec allows
          // standalone NOTs as a plain
          // negation 'ANY except <expr>'
          return false;
        $operator .= $token;
        break;
      // If token is not an operator ....
      default:
        // Strip junk irrelevant to us
        if(preg_match('/([a-zA-Z\d\-:\.\/]+)(?:[\?\*\+\$]|\^(?:[\+\-]|\d+(\-\d+)?))?/', trim($token), $t))
          $token = $t[1];
        debug_message('expression', "Token: \"".$token."\"");
        if(empty($token) || $token == ".")
          break;
        // Detect the type of operand
        // and expand it into a set of
        // associated ASNs
        $operand = array();
        // Token is ANY, AS-ANY or RS-ANY ?
        if(is_any($token)) {
          if($result_type & RPSL_PREFIX) {
            $operand = ($result_type & RPSL_OBJECTS) ?
                         array(
                           $default_network => array(
                             $route_type => $default_network,
                             'origin' => 'AS0'
                           )
                         ):
                         array($default_network);
            $op_type = RPSL_PREFIX;
          } else {
            $operand = array($token);
            $op_type = RPSL_AS;
          }
        // Token is an IPv4 prefix ?
        } elseif(is_ipv4($token)) {
          $operand = ($result_type & RPSL_OBJECTS) ?
                        route($token, $servers):
                        array($token);
          $op_type = RPSL_PREFIX;
        // Token is an IPv6 prefix ?
        } elseif(is_ipv6($token)) {
          $operand = ($result_type & RPSL_OBJECTS) ?
                        route6($token, $servers):
                        array($token);
          $op_type = RPSL_PREFIX;
        // Token is an AS number ?
        } elseif(is_asn($token)) {
          if($result_type & RPSL_PREFIX) {
            $routes = whois_query($token,
                                  $route_type,
                                  'origin',
                                  $servers);
            if(!empty($routes))
              $operand = ($result_type & RPSL_OBJECTS) ?
                            $routes:
                            array_keys($routes);
            $op_type = RPSL_PREFIX;
          } else {
            $operand = ($result_type & RPSL_OBJECTS) ?
                          aut_num($token, $servers):
                          array($token);
            $op_type = RPSL_AS;
          }
        // Token is an AS set ?
        } elseif(is_as_set($token)) {
          $as_set = expand_set($token, $servers);
          $op_type = RPSL_AS;
          if(!empty($as_set) && isset($as_set['members'])) {
            if($result_type & RPSL_PREFIX) {
              $routes = whois_query($as_set['members'],
                                    $route_type,
                                    'origin',
                                    $servers);
              if(!empty($routes))
                $operand = ($result_type & RPSL_OBJECTS) ?
                              $routes:
                              array_keys($routes);
              $op_type = RPSL_PREFIX;
            } elseif($result_type & RPSL_OBJECTS) {
              $aut_nums = whois_query($as_set['members'],
                                      'aut-num',
                                      NULL,
                                      $servers);
              if(!empty($aut_nums))
                $operand = $aut_nums;
            } else
              $operand = $as_set['members'];
          }
        // Token is a route set ?
        } elseif(is_route_set($token)) {
          $route_set = expand_set($token, $servers);
          $op_type = RPSL_PREFIX;
          if(!empty($route_set) && isset($route_set['members'])) {
            if($result_type & RPSL_OBJECTS) {
              $routes = whois_query($route_set['members'],
                                    $route_type,
                                    NULL,
                                    $servers);
              if(!empty($routes))
                $operand = $routes;
            } else
              $operand = $route_set['members'];
          }
        // Token is a filter ?
        } elseif(is_filter_set($token)) {
          $filter_set = filter_set($token, $servers);
          if(!empty($filter_set) && isset($filter_set['filter'])) {
            $operand = expand_expression($filter_set['filter'],
                                         $family,
                                         $result_type,
                                         $servers);
            if($operand === FALSE)
              return false;
          }
          // Detect the operand type
          $op_type = is_asn(($result_type & RPSL_OBJECTS) ?
                               array_keys($operand):$operand) ?
                                  RPSL_AS:
                                  RPSL_PREFIX;
        // Token cannot be identified
        } else
          return false;
        // If result type isn't specified, or
        // operand type matches the requested
        // result type, use it ... otherwise,
        // ignore it
        if(empty($result_type) ||
           $result_type & $op_type) {
          // If operator isn't set, assume OR ...
          if(empty($operator))
            $operator = 'OR';
          // Apply operand to the result
          switch($operator) {
            case 'AND':
              $result = ($result_type & RPSL_OBJECTS) ?
                           array_intersect_key($result, $operand):
                           array_intersect($result, $operand);
              break;
            case 'OR':
              $result = array_merge($result, $operand);
              break;
            case 'EXCEPT':
            case 'ANDNOT':
              $result = ($result_type & RPSL_OBJECTS) ?
                           array_diff_key($result, $operand):
                           array_diff($result, $operand);
              break;
            default:
              return false;
          }
          // If result type wasn't explicitly specified,
          // match the type of first processed operand
          if(empty($result_type))
            $result_type = $op_type;
        }
        // Clear operator
        unset($operator);
        break;
    }

  }

  // Returning result set here is valid
  // only if we were NOT called recursively.
  if(is_string($filter) && empty($tokens)) {
    // Remove duplicate entries
    if($result_type & RPSL_OBJECTS)
      $objects = array_keys($result);
    else
      $objects = $result = array_keys(array_flip($result));
    // Dump the result if debugging is on
    debug_message('expression', "Expression \"".$filter."\" expands to:", $objects);
    // Return the expression result
    return $result;
  }
  // If we were called recursively, getting
  // to this point means subexpression was
  // NOT terminated properly
  return false;
}

function expand_set($set_name, &$servers=NULL)
{
  static $cache;

  // Don't waste time ...
  if(empty($set_name))
    return;

  // We always use uppercase names
  $set_name = strtoupper($set_name);

  // If RPSL set has already been expanded ...
  if(isset($cache[$set_name]) &&
     is_rpsl_object($cache[$set_name]))
    // ... just return it from cache
    return $cache[$set_name];

  // Determine the set type
  if(is_as_set($set_name))
    $object_type = 'as-set';
  elseif(is_route_set($set_name))
    $object_type = 'route-set';
  else
    return;

  // This will hold all expanded members
  $set_members = array();

  // Add the set to the expansion list
  $expand_sets = array($set_name);
  // Add the set to the list of already expanded sets
  $expanded_sets = array($set_name => true);

  // Do the deep expansion
  while(!empty($expand_sets)) {

    // Retrieve RPLS sets
    $sets = whois_query($expand_sets,
                        $object_type,
                        NULL,
                        $servers);

    if(empty($sets))
      break;

    // Begin with an empty list of sets to expand.
    // This list will be used in the next iteration.
    $expand_sets = array();

    foreach($sets as $key => $set) {

      // If what we have is not a RPSL set object, skip it
      if(!is_rpsl_object($set) || !isset($set['members']))
        continue;

      // The list of unique members expressions
      $members = is_array($set['members']) ?
                   $set['members']:array($set['members']);

      foreach($members as $member) {
        // If member is not a RPSL set ...
        if(!is_rpsl_set($member)) {
          // ... just store it along with the rest
          $set_members[$member] = true;
          debug_message('rpsl', "Set ".$key." member ".$member);
        // Otherwise, if member is a RPSL set,
        // unless it is already expanded ...
        } elseif(!isset($expanded_sets[$member])) {
          // ... add it to the expansion list
          $expand_sets[] = $member;
          // Mark set as expanded to prevent loops
          $expanded_sets[$member] = true;
          debug_message('rpsl', "Set ".$key." member ".$member." (to be recursively expanded)");
        } else
          debug_message('rpsl', "Set ".$key." member ".$member." already expanded.");
      }

    }

  }

  // If our expanded set has no members ...
  if(empty($set_members))
    // ... return nothing
    return;

  // Finalize our fully expanded set
  $expanded_set = array(
    $object_type => $set_name,
    'members'    => array_keys($set_members),
  );
  // Cache it
  $cache[$set_name] = $expanded_set;
  // Return it
  return $expanded_set;
}

function get_export_from_to($from_asn, $to_asn, $family=AF_INET, &$servers=NULL)
{
  // Don't waste time ...
  if(empty($from_asn) || empty($to_asn))
    return;

  // Fetch upstream AS's aut-num object
  $upstream = aut_num($from_asn, $servers);
  if(empty($upstream))
    return;

  // Get whatever upstream AS is
  // exporting to downstream AS
  if(isset($upstream['export'][$family][$to_asn])) {
    $exported = $upstream['export'][$family][$to_asn];
  // If downstream AS is missing
  // from export attributes ...
  } else {
    // ... look for it inside as/route/filter sets
    // upstream AS is exporting to
    foreach(preg_grep('/^(?:(?:AS\d+:)?AS|RS|FLTR)\-(?!ANY)/', array_keys($upstream['export'][$family])) as $to_set) {
      // Expand set
      $downstreams = expand_expression($to_set, $family, RPSL_AS, $servers);
      // If downstream AS is a member of
      // examined as/route/filter set ...
      if(!empty($to_set) && in_array($to_asn, $downstreams)) {
        // ... use that export attribute
        $exported = $upstream['export'][$family][$to];
        break;
      }
    }
    // If downstream AS is not a member of any
    // as-sets found in export attributes ...
    if(empty($exported)) {
      // ... look for wildcard AS-ANY ...
      if(isset($upstream['export'][$family]['AS-ANY']))
        $exported = $upstream['export'][$family]['AS-ANY'];
      // ... or ANY
      elseif(isset($upstream['export'][$family]['ANY']))
        $exported = $upstream['export'][$family]['ANY'];
    }
  }

  // If we still don't have any exports ...
  if(empty($exported))
    // ... we are not supposed to receive anything
    return;

  // Parse export filter and expand it
  // into a bunch of route objects
  $routes = expand_expression($exported, $family, RPSL_PREFIX|RPSL_OBJECTS, $servers);
  // If we failed to expand ...
  if(empty($routes))
    // ... abort
    return;

  return $routes;
}

function trace_as_paths($from_asn, $to_asn, $family=AF_INET, &$servers=NULL, $loop_free_path=array(), &$as_paths=array())
{
  // If announcements source and/or receiver are missing ...
  if(empty($from_asn) || empty($to_asn))
    // ... this path doesn't lead anywhere
    return;

  // Get upstream AS's aut-num object
  $upstream = aut_num($from_asn, $servers);

  // If aut-num couldn't be found ...
  if(empty($upstream)) {
    debug_message('as-path', "Broken AS path: upstream ".$from_asn." not found.");
    // ... aut-num chain is broken and thus the AS path
    return;
  }

  // If upstream aut-num is missing  export attributes ....
  if(!(isset($upstream['export']) &&
       isset($upstream['export'][$family]))) {
    debug_message('as-path', "Broken AS path: upstream ".$from_asn." is missing export attributes for specified address family.");
    // ... aut-num chain is broken and thus the AS path
    return;
  }

  // Get downstream AS's aut-num object
  $downstream = aut_num($to_asn, $servers);

  // If aut-num couldn't be found ...
  if(empty($downstream)) {
    debug_message('as-path', "Broken AS path: downstream ".$to_asn." not found.");
    // ... aut-num chain is broken and thus the AS path
    return;
  }

  // If downstream aut-num is missing import attributes ....
  if(!(isset($downstream['import']) &&
       isset($downstream['import'][$family]))) {
    debug_message('as-path', "Broken AS path: downstream ".$to_asn." is missing import attributes for specified address family.");
    // ... aut-num chain is broken and thus the AS path
    return;
  }

  // Recurring path elements are a sign of
  // existing path loop(s). To break a loop ...
  if(in_array($from_asn, $loop_free_path)) {
    debug_message('as-path', "Loop detected: upstream ".$from_asn." already present in [", $loop_free_path, "].");
    // ... skip ASNs already present in the current path
    return;
  }

  // Add upstream AS to the path
  $loop_free_path[] = $from_asn;

  $exported = NULL;

  // Get whatever upstream AS is
  // exporting to downstream AS
  if(isset($upstream['export'][$family][$to_asn])) {
    $exported = $upstream['export'][$family][$to_asn];
  // If downstream AS is missing
  // from export attributes ...
  } else {
    // ... look for it inside as/route/filter sets
    // upstream AS is exporting to
    foreach(preg_grep('/^(?:AS\d+:)?AS\-(?!ANY)/', array_keys($upstream['export'][$family])) as $to_set) {
      // Expand set
      $downstreams = expand_expression($to_set, $family, RPSL_AS, $servers);
      // If downstream AS is a member of
      // examined as/route/filter set ...
      if(!empty($downstreams) && in_array($to_asn, $downstreams)) {
        // ... use that export attribute
        $exported = $upstream['export'][$family][$to_set];
        break;
      }
    }
    // If downstream AS is not a member of any
    // sets found in export attributes ...
    if(empty($exported)) {
      // ... look for wildcard AS-ANY ...
      if(isset($upstream['export'][$family]['AS-ANY']))
        $exported = $upstream['export'][$family]['AS-ANY'];
      // ... or ANY
      elseif(isset($upstream['export'][$family]['ANY']))
        $exported = $upstream['export'][$family]['ANY'];
    }
  }

  // If nothing is exported to downstream AS ...
  if(empty($exported)) {
    debug_message('as-path', "Broken AS path: ".$from_asn." is not exporting anything to ".$to_asn.".");
    // ... this path is a dead-end
    return;
  }

  $imported = NULL;

  // Get whatever downstream AS is
  // importing from upstream AS
  if(isset($downstream['import'][$family][$from_asn])) {
    $imported = $downstream['import'][$family][$from_asn];
  // If upstream AS is missing
  // from import attributes ...
  } else {
    // ... look for it inside as/route/filter sets
    // downstream AS is importing from
    foreach(preg_grep('/^(?:AS\d+:)?AS\-(?!ANY)/', array_keys($downstream['import'][$family])) as $from_set) {
      // Expand set
      $upstreams = expand_expression($from_set, $family, RPSL_AS, $servers);
      // If upstream AS is a member of
      // examined as/route/filter set ...
      if(!empty($upstreams) && in_array($from_asn, $upstreams)) {
        // ... use that import attribute
        $imported = $downstream['import'][$family][$from_set];
        break;
      }
    }
    // If upstream AS is not a member of any
    // as-sets found in import attributes ...
    if(empty($imported)) {
      // ... look for wildcard AS-ANY ...
      if(isset($downstream['import'][$family]['AS-ANY']))
        $imported = $downstream['import'][$family]['AS-ANY'];
      // ... or ANY
      elseif(isset($downstream['import'][$family]['ANY']))
        $imported = $downstream['import'][$family]['ANY'];
    }
  }

  // If nothing is imported from upstream AS ...
  if(empty($imported)) {
    debug_message('as-path', "Broken AS path: ".$to_asn." is not importing anything from ".$from_asn.".");
    // ... this path is a dead-end
    return;
  }

  $import_list = expand_expression($imported, $family, RPSL_AS, $servers);
  if(empty($import_list))
    $import_list = array();

  debug_message('as-path', $to_asn." is importing ".$imported." from ".$from_asn);

  $export_list = expand_expression($exported, $family, RPSL_AS, $servers);
  if(empty($export_list))
    $export_list = array();

  debug_message('as-path', $from_asn." is exporting ".$exported." to ".$to_asn);

  // If upstream AS is exporting ANY while
  // downstream AS is importing ANY ...
  if(is_any($imported) && is_any($exported)) {
    debug_message('as-path', "Broken AS path: cannot trace path if ".$to_asn." is importing ANY from ".$from_asn." while ".$from_asn." is exporting ANY to ".$to_asn.".");
    // ... the aut-num chain is broken
    // and thus the AS path
    return;
  }

  // This is the actual list of ASNs that
  // can be exchanged between upstream AS
  // and downstream AS. In other words,
  // only these ASNs are present in both
  // the export list of the upstream and
  // the import list of the downstream,
  // either directly or indirectly.
  if(is_any($imported))
    $exchange_list = &$export_list;
  elseif(is_any($exported))
    $exchange_list = &$import_list;
  else
    $exchange_list = array_intersect($export_list, $import_list);

  // If objects exported by upstream AS
  // are not imported by downstream AS ...
  if(count($exchange_list) < 1) {
    debug_message('as-path', "Broken AS path: cannot trace path if ".$to_asn." is not importing anything that ".$from_asn." is exporting.");
    // ... the aut-num chain is broken
    // and so is the AS path
    return;
  }

  // Sadly, some people don't properly maintain their
  // registry objects, leaving duplicate as-set members
  // which Whois/IRR servers don't protect us from,
  // resulting in duplicate AS paths. To get rid of
  // duplicates, the easiest (and probably the fastest)
  // way is to 'hash' AS paths themselves and use them
  // as associative array keys. That way, two identical
  // AS paths will end up under the same key, thus always
  // leaving only a single copy of each unique AS path.
  $origin = end($loop_free_path);
  $unique_key = implode(',', $loop_free_path);
  $as_paths[$origin][$unique_key] = $loop_free_path;
  debug_message('as-path', "AS path to ".$origin." is complete [".$unique_key."].");
  // Fetch everything in the exchange list in a single
  // pass to warm up the cache before branching
  whois_query($exchange_list, 'aut-num', NULL, $servers);

  // Determine whether to branch current AS path:
  // We will follow registry objects advertised by
  // the upstream and accepted by the downstream AS
  // in reverse, towards the path origin(s).
  foreach($exchange_list as $upstream_asn) {
    // If AS is announcing itself, we have reached
    // the origin of that AS path, thus the tracing
    // is terminated on this branch of the AS tree
    if($upstream_asn == $from_asn)
      continue;
    // Trace AS paths upstream, towards their origin,
    // from current upstream AS, through all links it
    // has established via import/export attributes
    // with ASes that made it through to downstream AS.
    // The premise is - in order to announce those ASes
    // to downstream AS, it has to receive (from) them
    // first, thus we can use the exchange list to
    // explore paths upstream to current upstream AS.
    trace_as_paths($upstream_asn,
                   $from_asn,
                   $family,
                   $servers,
                   $loop_free_path,
                   $as_paths);
  }

  return $as_paths;
}

function get_announced_prefixes($from_asn, $to_asn, $family=AF_INET, $include_as_paths=false, $validate_as_paths=false, &$servers=NULL)
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
    // Determine AF-specific parameters
    switch($family) {
      case AF_INET:
        $object_type = 'route';
        break;
      case AF_INET6:
        $object_type = 'route6';
        break;
      default:
        return;
    }
    // Get list of exports by <from_asn> to <to_asn>
    $routes = get_export_from_to($from_asn, $to_asn, $family, $servers);
    // If query suceeded ...
    if(!empty($routes))
      // ... proceed to the next phase
      break;
    // Report failure
    debug_message('info', "Query produced no usable results.");
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
      debug_message('info', "Trying the next server.");
    }
  }

  // If no exports could be found ...
  if(empty($routes))
    // ... abort
    return;

  // If AS path information is required ...
  if(($include_as_paths || $validate_as_paths)) {

    // Create a tree of loop free AS paths
    $as_paths = trace_as_paths($from_asn,
                               $to_asn,
                               $family,
                               $servers,
                               array($to_asn));

    if(empty($as_paths))
      return;

  }

  $announced = array();

  foreach($routes as $prefix => $objects) {
    // Make sure this is always an array even
    // if it contains a single route object
    if(is_rpsl_object($objects))
      $objects = array($objects);
    // Process route objects
    foreach($objects as $route) {
      // If origin is missing, this could be
      // a negative cache hit, so skip it
      if(!isset($route['origin']))
        continue;
      // Get route's origin
      $asn = $route['origin'];
      // Skip prefix if originated by target ASN.
      // No point exporting it to itself.
      if($asn == $to_asn)
        continue;
      // If valid AS path must exist between
      // target AS and route's origin then
      // route's origin must be present
      // in the list of existing AS paths
      if($validate_as_paths &&
         (!isset($as_paths[$asn]) ||
          empty($as_paths[$asn]))) {
        debug_message('as-path', "Discarding prefix ".$prefix.", AS path to origin ".$asn." is not known.");
        continue;
      }
      // If AS path information is required,
      // and at least one AS path exists
      // between target AS and route's origin ...
      if($include_as_paths && 
         isset($as_paths[$asn]))
        // ... store AS path(s) for this prefix
        // into announced list
        $announced['as_paths'][$asn] = $as_paths[$asn];
      // Store prefixes into announced list
      $announced['prefixes'][$asn][] = $prefix;
    }
  }

  return $announced;
}

?>
