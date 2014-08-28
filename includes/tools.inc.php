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
  // accross the prefix list
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
  // accross the prefix list
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
    // Stupid PHP: this is the only way to get around
    // signed long integers on 32-bit machines
    if(PHP_INT_SIZE == 4)
      $network = sprintf('%u', $network);
    // network => cidr
    $prefixes[$network] = $cidr;
  }
  // We are now ready to aggregate
  $prefixes = (PHP_INT_SIZE == 4) ?
                 prefix_aggregator32($prefixes):
                 prefix_aggregator64($prefixes);
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
