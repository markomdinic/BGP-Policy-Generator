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

function drop_privileges()
{
  global $config;
  // Must be running as root to do this
  if(posix_geteuid() != 0)
    return false;
  // If user is defined ...
  if(!empty($config['user'])) {
    $user = posix_getpwnam($config['user']);
    if($user === FALSE)
      return false;
  }
  // If group is defined ...
  if(!empty($config['group'])) {
    $group = posix_getgrnam($config['group']);
    if($group === FALSE)
      return false;
  }
  // If group data is valid ...
  if(is_array($group)) {
    // ... drop privileges to the defined group
    posix_setgid($group['gid']);
    posix_setegid($group['gid']);
  }
  // If user data is valid ...
  if(is_array($user)) {
    // ... drop privileges to the defined user
    posix_setuid($user['uid']);
    posix_seteuid($user['uid']);
  }
}

function status_message($msg, &$log=NULL)
{
  if(empty($msg))
    return '';

  // Show status message
  echo($msg."\n");
  // Accumulate messages in the log
  if(isset($log))
    $log .= $msg."\n";
}

function debug_message()
{
  global $config;

  if(!isset($config['debug']) ||
      empty($config['debug']))
    return;

  $args = func_get_args();
  if(empty($args))
    return;

  $category = array_shift($args);
  if(empty($category))
    return;

  $debug = is_array($config['debug']) ?
             $config['debug']:
             array(($config['debug'] === true) ?
                            'info':$config['debug']);

  // Bitmask of requested debug categories
  $debug_mask = array_sum(array_map('constant', $debug));
  // Bitmask that represents this message's category
  $category_mask = constant($category);
  if(!isset($category_mask)) {
    $category = 'info';
    $category_mask = 1;
  }

  if($category_mask & $debug_mask) {

    $message = "";

    foreach($args as $part) {

      if(is_string($part))
        $message .= $part;
      elseif(is_sequential_array($part))
        $message .= preg_match('/[\[\(\{\'\"]\s*$/', $message) ?
                       implode(' ', $part):
                       '"'.implode('", "', $part).'"';
      elseif(is_associative_array($part))
        $message .= print_r($part, true);

      $message .= " ";
    }

    echo("[".$category."] ".trim($message)."\n");
  }
}

function is_sequential_array(&$array)
{
  if(!is_array($array))
    return false;

  return array_keys($array) === range(0, count($array)-1);
}

function is_associative_array(&$array)
{
  if(!is_array($array))
    return false;

  return array_keys($array) !== range(0, count($array)-1);
}

function is_positive(&$value)
{
  if(empty($value))
    return false;

  return (is_numeric($value) && $value >= 0) ? true:false;
}

function is_port(&$port)
{
  if(empty($port))
    return false;

  return (is_numeric($port) && $port >= 0 && $port <= 65535) ? true:false;
}

function is_rpsl_object(&$object)
{
  return is_associative_array($object);
}

function is_name($names)
{
  if(empty($names))
    return false;

  if(!is_array($names))
    $names = array($names);

  foreach($names as $name) {
    if(!preg_match('/^[a-zA-Z0-9\-\.\_]+$/', $name))
      return false;
  }

  return true;
}

function is_asn($asns)
{
  if(empty($asns))
    return false;

  if(!is_array($asns))
    $asns = array($asns);

  foreach($asns as $asn) {
    if(!preg_match('/^(?:AS)?(\d+)$/i', $asn, $m))
      return false;
    if($m[1] < 1 || $m[1] > 4294967294)
      return false;
  }

  return true;
}

function is_any($value)
{
  if(empty($value) || !is_string($value))
    return false;

  return preg_match('/^(?:[AR]S\-)?ANY$/i', $value) ? true:false;
}

function is_as_set($value)
{
  if(empty($value) || !is_string($value))
    return false;

  return preg_match('/^(?:AS\d+:)?AS\-(?!ANY)/i', $value) ? true:false;
}

function is_route_set($value)
{
  if(empty($value) || !is_string($value))
    return false;

  return preg_match('/^RS\-/i', $value) ? true:false;
}

function is_filter_set($value)
{
  if(empty($value) || !is_string($value))
    return false;

  return preg_match('/^FLTR\-/i', $value) ? true:false;
}

function is_rpsl_set($value)
{
  if(empty($value) || !is_string($value))
    return false;

  return preg_match('/^(?:(?:AS\d+:)?AS|RS)\-(?!ANY)/i', $value) ? true:false;
}

function is_ipv4($prefixes)
{
  if(empty($prefixes))
    return false;

  if(!is_array($prefixes))
    $prefixes = array($prefixes);

  foreach($prefixes as $prefix) {
    if(!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $prefix))
      return false;
  }

  return true;
}

function is_ipv6($prefixes)
{
  if(empty($prefixes))
    return false;

  if(!is_array($prefixes))
    $prefixes = array($prefixes);

  foreach($prefixes as $prefix) {
    if(!preg_match('/^(?:((?=(?>.*?(::))(?!.*?\2)))\2?|([\da-f]{1,4}(?:\2|:\b|(?=[^\da-f]|\b))|\1))(?3){7}\/\d{1,2}$/i', $prefix))
      return false;
  }

  return true;
}

function is_valid_subnet_size($size)
{
  // This basically determines if size is a power of 2,
  // as valid subnet sizes are powers of 2. If size is
  // a number that is a power of 2, it will have no bits
  // in common with the preceeding number.
  return ($size & ($size-1)) ? false:true;
}

function prefix_aggregator32($nonaggregated, $address_length=32)
{
  //
  // IP subnet aggregator function for 32-bit machines.
  //
  // It takes array of network => cidr pairs and produces
  // similar array of aggregated networks. It cannot always
  // aggregate everything in a single pass, so it may be
  // called recursively.
  //

  $num_nonaggregated = count($nonaggregated);

  // Add dummy prefix to make loop run one extra iteration.
  // Otherwise, last prefix in the list would've been lost
  // or we would have to duplicate a part of the code.
  $nonaggregated[sprintf('%u', ((1 << $address_length) - 2))] = $address_length;

  // Sort prefixes by network addresses in ascending order
  // to prevent searching for neighboring address blocks
  // across entire prefix list
  ksort($nonaggregated);

  // Get the first prefix in the list of sorted network addresses
  $pending_aggregated_block_network_address =  key($nonaggregated);
  // False previous broadcast addresses to get the loop running
  $prev_broadcast_address = $pending_aggregated_block_network_address - 1;
  $prev_aggregated_block_broadcast_address = $prev_broadcast_address;

  // This array will collect aggregated prefixes
  $aggregated = array();

  foreach($nonaggregated as $current_network_address => $cidr) {
    // Skip address blocks that fall into already aggregated range
    // or range of preceeding address block
    if(($prev_aggregated_block_broadcast_address >= $current_network_address) ||
       ($prev_broadcast_address >= $current_network_address))
      continue;
    // Network address of the subnet immediately following this one
    $next_network_address = $current_network_address + (1 << ($address_length - $cidr));
    //
    // Aggregated prefix must have a valid subnet size that is
    // a power of two and be divisible by it's subnet size, just
    // like any other prefix. Keep aggregating while this is true.
    // Once we get to the invalid subnet size, stop aggregating
    // current address block, store it and start the next one.
    //
    // Also ...
    //
    // As long as current network and previous broadcast address
    // are next to each other, we are in the same address block,
    // so keep aggregating. Once we hit different result, current
    // address block is done, sotre it and start the next one.
    //
    $candidate_aggregated_block_size = $next_network_address - $pending_aggregated_block_network_address;
    if(!is_valid_subnet_size($candidate_aggregated_block_size) ||
       (floatval($pending_aggregated_block_network_address) % floatval($candidate_aggregated_block_size)) ||
       ($current_network_address - $prev_broadcast_address > 1)) {
      // Calculate CIDR of aggregated prefix
      $hostmask = floatval($pending_aggregated_block_network_address) ^ floatval($prev_broadcast_address);
      $aggregated_block_prefix_length = $address_length;
      while($hostmask > 0) {
        $hostmask >>= 1;
        $aggregated_block_prefix_length--;
      }
      // If pending aggregated block lies outside previous aggregated block ...
      if($pending_aggregated_block_network_address > $prev_aggregated_block_broadcast_address) {
        // ... aggregated block is complete - add prefix to the list ...
        $aggregated[$pending_aggregated_block_network_address] = $aggregated_block_prefix_length;
        // ... and keep aggregated block's broadcast address
        $prev_aggregated_block_broadcast_address = $prev_broadcast_address;
      }
      // Begin aggregating next address block
      $pending_aggregated_block_network_address = $current_network_address;
    }
    // Broadcast address of current prefix
    // to be used in the next iteration
    $prev_broadcast_address = $next_network_address - 1;
  }

  // Recursion ends once no aggregation has occured.
  // We determine that when the number of produced
  // aggregated prefixes remains equal to the number
  // of input (non-aggregated) prefixes.
  if(count($aggregated) >= $num_nonaggregated)
    return $aggregated;

  // Otherwise, call self recursively
  // for the next aggregation pass
  return prefix_aggregator32($aggregated);
}

function prefix_aggregator64($nonaggregated, $address_length=32)
{
  //
  // IP subnet aggregator function for 64-bit machines.
  //
  // It takes array of network => cidr pairs and produces
  // similar array of aggregated networks. It cannot always
  // aggregate everything in a single pass, so it may be
  // called recursively.
  //

  $num_nonaggregated = count($nonaggregated);

  // Add dummy prefix to make loop run one extra iteration.
  // Otherwise, last prefix in the list would've been lost
  // or we would have to duplicate a part of the code.
  $nonaggregated[((1 << $address_length) - 2)] = $address_length;

  // Sort prefixes by network addresses in ascending order
  // to prevent searching for neighboring address blocks
  // across entire prefix list
  ksort($nonaggregated);

  // Get the first prefix in the list of sorted network addresses
  $pending_aggregated_block_network_address = key($nonaggregated);
  // False previous broadcast addresses to get the loop running
  $prev_broadcast_address = $pending_aggregated_block_network_address - 1;
  $prev_aggregated_block_broadcast_address = $prev_broadcast_address;

  // This array will collect aggregated prefixes
  $aggregated = array();

  foreach($nonaggregated as $current_network_address => $cidr) {
    // Skip address blocks that fall into already aggregated range
    // or range of preceeding address block
    if(($prev_aggregated_block_broadcast_address >= $current_network_address) ||
       ($prev_broadcast_address >= $current_network_address))
      continue;
    // Network address of the subnet immediately following this one
    $next_network_address = $current_network_address + (1 << ($address_length - $cidr));
    //
    // Aggregated prefix must have a valid subnet size that is
    // a power of two and be divisible by it's subnet size, just
    // like any other prefix. Keep aggregating while this is true.
    // Once we get to the invalid subnet size, stop aggregating
    // current address block, store it and start the next one.
    //
    // Also ...
    //
    // As long as current network and previous broadcast address
    // are next to each other, we are in the same address block,
    // so keep aggregating. Once we hit different result, current
    // address block is done, sotre it and start the next one.
    //
    $candidate_aggregated_block_size = $next_network_address - $pending_aggregated_block_network_address;
    if(!is_valid_subnet_size($candidate_aggregated_block_size) ||
       ($pending_aggregated_block_network_address % $candidate_aggregated_block_size) ||
       ($current_network_address - $prev_broadcast_address > 1)) {
      // Calculate CIDR of aggregated prefix
      $hostmask = $pending_aggregated_block_network_address ^ $prev_broadcast_address;
      $aggregated_block_prefix_length = $address_length;
      while($hostmask > 0) {
        $hostmask >>= 1;
        $aggregated_block_prefix_length--;
      }
      // If pending aggregated block lies outside previous aggregated block ...
      if($pending_aggregated_block_network_address > $prev_aggregated_block_broadcast_address) {
        // ... aggregated block is complete - add prefix to the list ...
        $aggregated[$pending_aggregated_block_network_address] = $aggregated_block_prefix_length;
        // ... and keep aggregated block's broadcast address
        $prev_aggregated_block_broadcast_address = $prev_broadcast_address;
      }
      // Begin aggregating next address block
      $pending_aggregated_block_network_address = $current_network_address;
    }
    // Broadcast address of current prefix
    // to be used in the next iteration
    $prev_broadcast_address = $next_network_address - 1;
  }

  // Recursion ends once no aggregation has occured.
  // We determine that when the number of produced
  // aggregated prefixes remains equal to the number
  // of input (non-aggregated) prefixes.
  if(count($aggregated) >= $num_nonaggregated)
    return $aggregated;

  // Otherwise, call self recursively
  // for the next aggregation pass
  return prefix_aggregator64($aggregated);
}

function filter_more_specific($nonaggregated, $address_length=32)
{
  // Sort prefixes by network addresses in ascending order
  // to prevent searching for neighboring address blocks
  // across entire prefix list
  ksort($nonaggregated);

  // Get the first prefix in the list of sorted network addresses
  $first_network_address =  key($nonaggregated);
  // False previous broadcast addresses to get the loop running
  $prev_supernet_broadcast_address = $first_network_address - 1;

  // This array will collect supernet prefixes
  $aggregated = array();

  foreach($nonaggregated as $current_network_address => $cidr) {
    // Calculate this subnet's broadcast address
    $current_broadcast_address = $current_network_address + (1 << ($address_length - $cidr)) - 1;
    // Keep only subnets that fall outside previous supernet's range
    if($prev_supernet_broadcast_address < $current_network_address ||
       $prev_supernet_broadcast_address < $current_broadcast_address) {
      // Prefix is a supernet - add it to the list ...
      $aggregated[$current_network_address] = $cidr;
      // Keep supernet's broadcast address
      $prev_supernet_broadcast_address = $current_broadcast_address;
    }
  }

  return $aggregated;
}

function aggregate_ipv4($prefix_list, $full=true)
{
  // Prefixes are given as an array of strings in CIDR format and
  // will be converted to numeric format and placed in this array.
  $prefixes = array();

  // Convert prefixes from string to numeric
  // network_integer => cidr_integer format
  foreach(array_unique($prefix_list) as $prefix) {
    // Split prefix into network and cidr parts
    @list($network, $cidr) = explode('/', $prefix);
    if(empty($network) || empty($cidr))
      continue;
    // Confert dotted decimal into integer format
    $network = ip2long($network);
    // Stupid PHP: this is the only way to get around
    // signed long integers on 32-bit machines. Addresses
    // above 127.255.255.255 are converted to negative
    // 32-bit integers. Converting them to unsigned int
    // represented as string circumvents the problem.
    if(PHP_INT_SIZE == 4)
      $network = sprintf('%u', $network);
    // Network address must be divisible by subnet size,
    // ignore prefixes with wrong prefix lengths.
    //
    // Both network address and block size are converted
    // to float to make this work on 32-bit machines.
    if(floatval($network) % floatval(1 << (32 - $cidr)))
      continue;
    // If network is already known, but prefix lengths
    // differ, use the less specific one, as it covers
    // the range of more specific one, as well.
    if(isset($prefixes[$network]) && $prefixes[$network] <= $cidr)
      continue;
    // network => cidr
    $prefixes[$network] = $cidr;
  }
  // We are now ready to aggregate
  if($full) {
    // Perform full prefix aggregation
    $prefixes = (PHP_INT_SIZE == 4) ?
                   prefix_aggregator32($prefixes):
                   prefix_aggregator64($prefixes);
  } else {
    // Eliminate only more specific prefixes
    // that overlap with less specific supernets
    $prefixes = filter_more_specific($prefixes);
  }
  // Make sure we don't try to convert an empty list
  if(empty($prefixes))
    return;
  $aggregated_prefixes = array();
  // Convert prefixes from numeric to CIDR string format
  foreach($prefixes as $network => $cidr)
    // Add aggregated block's prefix to the list
    $aggregated_prefixes[] = long2ip($network)."/".$cidr;
  // Aggregation is done
  return $aggregated_prefixes;
}

?>
