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

function is_asn($asn)
{
  if(preg_match('/^(?:AS)?(\d+)$/i', $asn, $m))
    if($m[1] >= 1 && $m[1] <= 4294967294)
      return true;

  return false;
}

function is_ipv4($prefix)
{
  if(preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/', $prefix))
    return true;

  return false;
}

function is_ipv6($prefix)
{
  if(preg_match('/^(?:((?=(?>.*?(::))(?!.*?\2)))\2?|([\da-f]{1,4}(?:\2|:\b|(?=[^\da-f]|\b))|\1))(?3){7}\/\d{1,2}$/i', $prefix))
    return true;

  return false;
}

function is_valid_subnet_size($size)
{
  // This basically determines if size is a power of 2,
  // as valid subnet sizes are powers of 2. If size is
  // a number that is a power of 2, it will have no bits
  // in common with the preceeding number.
  return ($size & ($size-1)) ? false:true;
}

function prefix_aggregator($nonaggregated)
{
  //
  // This is the IP subent aggregator function.
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
  $nonaggregated[0xFFFFFFFE] = 32;

  // Sort prefixes by network addresses in ascending order
  // to prevent searching for neighboring address blocks
  // accross the prefix list
  ksort($nonaggregated);

  // The list of sorted network addresses
  $networks = array_keys($nonaggregated);
  // First prefix in the list
  $aggregated_block_network_address = $networks[0];
  // False previous broadcast addresses
  // to get the loop up and running
  $prev_broadcast_address = $aggregated_block_network_address - 1;

  $aggregated = array();

  foreach($nonaggregated as $current_network_address => $cidr) {
    // Network address of the subnet immediately following this one
    $next_network_address = $current_network_address + (1 << (32 - $cidr));
    //
    // Aggregated prefix must be divisible by it's subnet size,
    // like any other prefix. Keep aggregating while this is true.
    // Once we get to the invalid subnet size, stop aggregating
    // current address block, store it and start the next one.
    //
    $aggregated_block_size = $next_network_address - $aggregated_block_network_address;
    //
    // As long as current network and previous broadcast address
    // are next to each other, we are in the same address block,
    // so keep aggregating. Once we hit different result, current
    // address block is done, sotre it and start the next one.
    //
    if(!is_valid_subnet_size($aggregated_block_size) ||
       ($aggregated_block_network_address % $aggregated_block_size) ||
       ($current_network_address - $prev_broadcast_address != 1)) {
      // Calculate CIDR of aggregated prefix
      $hostmask = $aggregated_block_network_address ^ $prev_broadcast_address;
      $aggregated_block_prefix_length = 32;
      while($hostmask > 0) {
        $hostmask >>= 1;
        $aggregated_block_prefix_length--;
      }
      // Broadcast address of aggregated block
      $aggregated_block_broadcast_address = $aggregated_block_network_address + (1 << (32 - $aggregated_block_prefix_length)) - 1;
      // Current address block must be outside
      // already aggregated address block
      if($current_network_address > $aggregated_block_broadcast_address) {
        // Add aggregated block's prefix to the list
        $aggregated[$aggregated_block_network_address] = $aggregated_block_prefix_length;
        // Begin aggregating next address block
        $aggregated_block_network_address = $current_network_address;
      }
    }
    // Broadcast address of current prefix
    // to be used in the next iteration
    $prev_broadcast_address = $next_network_address - 1;
  }

  // Recursion ends once no aggregation has occured.
  // We determine that when the number of produced
  // aggregated prefixes remains equal to the number
  // of input (non-aggregated) prefixes.
  if(count($aggregated) >= $num_nonaggregated) {
    $aggregated_prefixes = array();
    // Convert prefixes from numeric to CIDR string format
    foreach($aggregated as $network => $cidr)
      // Add aggregated block's prefix to the list
      $aggregated_prefixes[] = long2ip($network)."/".$cidr;
    // Aggregation is done
    return $aggregated_prefixes;
  }
  // Call self recursively for the next aggregation pass
  return prefix_aggregator($aggregated, $num_nonaggregated);
}

function aggregate_ipv4($prefix_list)
{

  // Prefixes are given as an array of strings in CIDR format and
  // will be converted to numeric format and placed in this array.
  $prefixes = array();

  // Convert prefixes from string to numeric
  // network_integer => cidr_integer format
  foreach(array_unique($prefix_list) as $prefix) {
    // Split prefix into network and cidr parts
    list($network, $cidr) = explode('/', $prefix);
    if(empty($network) || empty($cidr))
      continue;
    // Confert dotted decimal into integer format
    $network = ip2long($network);
    // Network address must be divisible by subnet size,
    // ignore prefixes with wrong prefix lengths
    if($network % (1 << (32 - $cidr)))
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
  return prefix_aggregator($prefixes);
}

?>
