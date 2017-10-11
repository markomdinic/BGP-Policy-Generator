<?php
/*

 Copyright (c) 2017 Marko Dinic. All rights reserved.

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

function policy_generate($template, &$ios_conf, &$include)
{
  foreach($template->getElementsByTagName('policy') as $policy) {
    // Route-map name is mandatory
    $policy_name = $policy->getAttribute('id');
    if(!is_name($policy_name))
      continue;

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'ios', 'prepend');
    if(!empty($ff))
      $ios_conf[] = $ff;

    $seq = 10;

    // Begin route-map
    $ios_conf[] = "no route-map ".$policy_name;
    foreach($policy->getElementsByTagName('term') as $term) {

      // Term action is mandatory
      switch($term->getAttribute('action')) {
        case 'permit':
        case 'accept':
          $action = "permit";
          break;
        case 'deny':
        case 'reject':
          $action = "deny";
          break;
        default:
          continue 2;
      }

      // Default to IPv4
      $family = "ip";

      // Begin term
      $ios_conf[] = "route-map ".$policy_name." ".$action." ".$seq++;

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'ios', 'prepend');
      if(!empty($ff))
        $ios_conf[] = $ff;

      // Match conditions
      foreach($term->getElementsByTagName('match') as $match) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'ios', 'prepend');
        if(!empty($ff))
          $ios_conf[] = $ff;

        // Family
        foreach($match->getElementsByTagName('family') as $f) {
          // Family name is mandatory
          switch($f->nodeValue) {
            case 'inet':
            case 'ipv4':
              $family = "ip";
              break;
            case 'inet6':
            case 'ipv6':
              $family = "ipv6";
              break;
            default:
              continue 2;
          }
          break;
        }
        // Protocol
        foreach($match->getElementsByTagName('protocol') as $p) {
          // Router process ID is mandatory
          $id = $p->getAttribute('id');
          if(!is_numeric($id))
            continue;
          // Protocol name is mandatory
          $protocol_name = $p->nodeValue;
          // Template protocol names => Cisco protocol names
          switch($protocol_name) {
            case 'local':
            case 'direct':
              $protocol_name = "connected";
              break;
            case 'aggregate':
              $protocol_name = "static";
              break;
            case 'rip1':
            case 'rip2':
            case 'ripv1':
            case 'ripv2':
              $protocol_name = "rip";
              break;
            case 'ospf2':
            case 'ospf3':
              $protocol_name = "ospf";
              break;
            case 'connected':
            case 'static':
            case 'rip':
            case 'bgp':
            case 'ospf':
            case 'eigrp':
            case 'isis':
              break;
            default:
              continue 2;
          }
          // Insert match line
          $ios_conf[] = " match source-protocol ".$protocol_name." ".$id;
        }
        // Prefix list
        foreach($match->getElementsByTagName('prefix-list') as $p) {
          // Prefix list name is mandatory
          $prefix_list_name = $p->nodeValue;
          if(empty($prefix_list_name))
            continue;
          // Insert match line
          $ios_conf[] = " match ".$family." address prefix-list ".$prefix_list_name;
          // Include prefix list definition ?
          switch($p->getAttribute('include')) {
            case 'true':
            case 'yes':
            case 'on':
            case '1':
              // Add prefix list name to the inclusion list
              include_config($include, 'prefixlist', $prefix_list_name);
              break;
          }
        }
        // Community
        foreach($match->getElementsByTagName('community') as $c) {
          // Community list name is mandatory
          $community_list_name = $c->nodeValue;
          if(empty($community_list_name))
            continue;
          // Insert match line
          $ios_conf[] = " match community ".$community_list_name;
        }
        // AS-path
        foreach($match->getElementsByTagName('as-path') as $a) {
          // AS-path access list number is mandatory for Cisco
          $aspath_acl = $a->getAttribute('id');
          if(!is_numeric($aspath_acl))
            continue;
          // Insert match line
          $ios_conf[] = " match as-path ".$aspath_acl;
        }
        // Neighbor
        foreach($match->getElementsByTagName('neighbor') as $n) {
          // Access list matching neighbor(s) is mandatory for Cisco
          $neighbor_prefix_list = $n->getAttribute('id');
          if(empty($neighbor_prefix_list))
            continue;
          // Insert match line
          $ios_conf[] = " match ".$family." route-source prefix-list ".$neighbor_prefix_list;
        }

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'ios', 'append');
        if(!empty($ff))
          $ios_conf[] = $ff;

      }

      // Set/change attributes
      foreach($term->getElementsByTagName('set') as $set) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'ios', 'prepend');
        if(!empty($ff))
          $ios_conf[] = $ff;

        // AS-path prepend
        foreach($set->getElementsByTagName('prepend') as $p) {
          $prepend = $p->nodeValue;
          if(empty($prepend))
            continue;
          // Insert set line
          $ios_conf[] = " set as-path prepend ".$prepend;
          break;
        }
        // Multi-exit discriminator (MED)
        foreach($set->getElementsByTagName('med') as $m) {
          // MED amount is mandatory
          $metric = $m->nodeValue;
          if(!is_numeric($metric))
            continue;
          // Template MED action => Cisco MED action
          switch($m->getAttribute('action')) {
              case '+':
              case 'add':
                $ios_conf[] = " set metric +".$metric;
                break;
              case '-':
              case 'sub':
              case 'subtract':
                $ios_conf[] = " set metric -".$metric;
                break;
              default:
                $ios_conf[] = " set metric ".$metric;
                break;
          }
          break;
        }
        // Local preference
        foreach($set->getElementsByTagName('local-preference') as $l) {
          // Local preference amount is mandatory
          $local_preference = $l->nodeValue;
          if(!is_numeric($local_preference))
            continue;
          // Insert set line
          $ios_conf[] = " set local-preference ".$local_preference;
          break;
        }
        // Weight
        foreach($set->getElementsByTagName('weight') as $w) {
          // Weight amount is mandatory
          $weight = $w->nodeValue;
          if(!is_numeric($weight))
            continue;
          // Insert set line
          $ios_conf[] = " set weight ".$weight;
          break;
        }
        // Origin
        foreach($set->getElementsByTagName('origin') as $o) {
          switch($o->nodeValue) {
            case 'i':
            case 'igp':
              $ios_conf[] = " set origin igp";
              break;
            case '?':
            case 'incomplete':
              $ios_conf[] = " set origin incomplete";
              break;
          }
          break;
        }
        // Communities
        foreach($set->getElementsByTagName('community') as $c) {
          $community = $c->nodeValue;
          // Community action is mandatory
          switch($c->getAttribute('action')) {
            case '=':
            case 'set':
              // Community is mandatory for set action
              if(!empty($community))
                $ios_conf[] = " set community ".$community;
              break;
            case '+':
            case 'add':
              // Community is mandatory for add action
              if(!empty($community))
                $ios_conf[] = " set community ".$community." additive";
              break;
            case '-':
            case 'delete':
              // Community-list name is required for delete
              $name = $c->getAttribute('id');
              if(!empty($name))
                $ios_conf[] = " set comm-list ".$name." delete";
              break;
            default:
              continue 2;
          }
        }
        // Next-hop
        foreach($set->getElementsByTagName('next-hop') as $n) {
          // Next hop value is mandatory
          $next_hop = $n->nodeValue;
          if(empty($next_hop))
            continue;
          switch($next_hop) {
            case 'self':
              $ios_conf[] = " set ".$family." next-hop self";
              break;
            case 'peer':
            case 'peeraddress':
            case 'peer-address':
            case 'peer_address':
              $ios_conf[] = " set ".$family." next-hop peer-address";
              break;
            default:
              $ios_conf[] = " set ".$family." next-hop ".$next_hop;
              break;
          }
          break;
        }

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'ios', 'append');
        if(!empty($ff))
          $ios_conf[] = $ff;

      }

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'ios', 'append');
      if(!empty($ff))
        $ios_conf[] = $ff;

      // Route-map statement is done
      $ios_conf[] = " exit";
    }

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'ios', 'append');
    if(!empty($ff))
      $ios_conf[] = $ff;

  }

  return true;
}

?>
