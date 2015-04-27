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

function policy_generate($template, &$junos_conf, &$include)
{
  foreach($template->getElementsByTagName('policy') as $policy) {
    // Policy name is mandatory
    $policy_name = $policy->getAttribute('id');
    if(!is_name($policy_name))
      continue;

    // Begin policy statement
    $junos_conf[] = "policy-statement ".$policy_name." {";

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'junos', 'prepend');
    if(!empty($ff))
      $junos_conf[] = $ff;

    foreach($policy->getElementsByTagName('term') as $term) {

      // Term name is mandatory
      $term_name = $term->getAttribute('id');
      if(!is_name($term_name))
        continue;

      $depth = 1;
      $pad = str_pad('', 4*$depth++);

      // Begin term
      $junos_conf[] = $pad."term ".$term_name." {";
      $pad = str_pad('', 4*$depth++);

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'junos', 'prepend');
      if(!empty($ff))
        $junos_conf[] = $ff;

      // Match conditions
      $match_conf = array();
      $pad = str_pad('', 4*$depth);

      foreach($term->getElementsByTagName('match') as $match) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'junos', 'prepend');
        if(!empty($ff))
          $match_conf[] = $ff;

        // Family
        foreach($match->getElementsByTagName('family') as $f) {
          // Family name is mandatory
          switch($f->nodeValue) {
            case 'inet':
            case 'ipv4':
              $match_conf[] = $pad."family inet;";
              break;
            case 'inet6':
            case 'ipv6':
              $match_conf[] = $pad."family inet6;";
              break;
          }
          break;
        }
        // Protocol
        $protocols = array();
        foreach($match->getElementsByTagName('protocol') as $p) {
          $proto = $p->nodeValue;
          switch($proto) {
            case 'connected':
              $protocols[] = "direct";
              break;
            case 'rip1':
            case 'rip2':
            case 'ripv1':
            case 'ripv2':
              $protocols[] = "rip";
              break;
            case 'rip':
            case 'ripng':
            case 'direct':
            case 'static':
            case 'local':
            case 'bgp':
            case 'ospf':
            case 'ospf2':
            case 'ospf3':
            case 'access':
            case 'aggregate':
            case 'isis':
              $protocols[] = $proto;
              break;
          }
        }
        $num = count($protocols);
        if($num)
          $match_conf[] = $pad."protocol ".($num > 1 ? "[ ":"").implode(' ', $protocols).($num > 1 ? " ]":"").";";
        // Prefix list
        foreach($match->getElementsByTagName('prefix-list') as $p) {
          // Prefix list name is mandatory
          $prefix_list_name = $p->nodeValue;
          if(empty($prefix_list_name))
            continue;
          switch($p->getAttribute('match')) {
            case 'longer':
              $match_conf[] = $pad."prefix-list-filter ".$prefix_list_name." longer;";
              break;
            case 'orlonger':
              $match_conf[] = $pad."prefix-list-filter ".$prefix_list_name." orlonger;";
              break;
            default:
              $match_conf[] = $pad."prefix-list-filter ".$prefix_list_name." exact;";
              break;
          }
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
        // AS-path
        $aspaths = array();
        foreach($match->getElementsByTagName('as-path') as $a) {
          // AS-path is mandatory
          $aspath = $a->nodeValue;
          if(!empty($aspath))
            $aspaths[] = $aspath;
        }
        $num = count($aspaths);
        if($num)
          $match_conf[] = $pad."as-path ".($num > 1 ? "[ ":"").implode(' ', $aspaths).($num > 1 ? " ]":"").";";
        // Community
        $communities = array();
        foreach($match->getElementsByTagName('community') as $c) {
          // Community name is mandatory
          $community = $c->nodeValue;
          if(!empty($community))
            $communities[] = $community;
        }
        $num = count($communities);
        if($num)
          $match_conf[] = $pad."community ".($num > 1 ? "[ ":"").implode(' ', $communities).($num > 1 ? " ]":"").";";
        // Neighbor
        $neighbors = array();
        foreach($match->getElementsByTagName('neighbor') as $n) {
          // Neighbor address is mandatory
          $neighbor = $n->nodeValue;
          if(!empty($neighbor))
            $neighbors[] = $neighbor;
        }
        $num = count($neighbors);
        if($num)
          $match_conf[] = $pad."neighbor ".($num > 1 ? "[ ":"").implode(' ', $neighbors).($num > 1 ? " ]":"").";";

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'junos', 'append');
        if(!empty($ff))
          $match_conf[] = $ff;

        // There can be only one <match> within <term>
        break;
      }

      $pad = str_pad('', 4*($depth-1));

      // If there's at least one match condition,
      // create match section inside the term
      if(!empty($match_conf)) {
        $junos_conf[] = $pad."from {";
        $junos_conf[] = implode("\n", $match_conf);
        $junos_conf[] = $pad."}";
      }

      // Set/change attributes
      $junos_conf[] = $pad."then {";
      $pad = str_pad('', 4*$depth);

      foreach($term->getElementsByTagName('set') as $set) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'junos', 'prepend');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // AS-path prepend
        foreach($set->getElementsByTagName('prepend') as $p) {
          // AS-path prepend string is mandatory
          $prepend = $p->nodeValue;
          if(!empty($prepend))
            $junos_conf[] = $pad."as-path-prepend \"".$prepend."\";";
          break;
        }
        // Multi-exit discriminator (MED)
        foreach($set->getElementsByTagName('med') as $m) {
          // MED amount is mandatory
          $metric = $m->nodeValue;
          if(is_numeric($metric))
            $junos_conf[] = $pad."metric ".$metric.";";
          break;
        }
        // Protocol preference (administrative distance)
        foreach($set->getElementsByTagName('protocol-preference') as $p) {
          // Preference amount is mandatory
          $preference = $p->nodeValue;
          if(!is_numeric($preference))
            continue;
          switch($p->getAttribute('action')) {
            case '+':
            case 'add':
              $junos_conf[] = $pad."preference add ".$preference.";";
              break;
            case '-':
            case 'sub':
            case 'subtract':
              $junos_conf[] = $pad."preference subtract ".$preference.";";
              break;
            default:
              $junos_conf[] = "preference ".$preference.";";
              break;
          }
          break;
        }
        // Local preference
        foreach($set->getElementsByTagName('local-preference') as $l) {
          // Local preference amount is mandatory
          $preference = $l->nodeValue;
          if(!is_numeric($preference))
            continue;
          switch($l->getAttribute('action')) {
            case '+':
            case 'add':
              $junos_conf[] = $pad."local-preference add ".$preference.";";
              break;
            case '-':
            case 'sub':
            case 'subtract':
              $junos_conf[] = $pad."local-preference subtract ".$preference.";";
              break;
            default:
              $junos_conf[] = $pad."local-preference ".$preference.";";
              break;
          }
          break;
        }
        // Origin
        foreach($set->getElementsByTagName('origin') as $o) {
          // Origin spec is mandatory
          switch($o->nodeValue) {
            case 'i':
            case 'igp':
              $junos_conf[] = $pad."origin igp;";
              break;
            case 'e':
            case 'egp':
              $junos_conf[] = $pad."origin egp;";
              break;
            case '?':
            case 'incomplete':
              $junos_conf[] = $pad."origin incomplete;";
              break;
          }
          break;
        }
        // Communities
        foreach($set->getElementsByTagName('community') as $c) {
          // Community name is mandatory
          $name = $c->getAttribute('id');
          if(empty($name))
            continue;
          // Community action is mandatory
          $action = $c->getAttribute('action');
          if(empty($action))
            continue;
          switch($action) {
            case '=':
            case 'set':
              $junos_conf[] = $pad."community set ".$name.";";
              break;
            case '+':
            case 'add':
              $junos_conf[] = $pad."community add ".$name.";";
              break;
            case '-':
            case 'delete':
              $junos_conf[] = $pad."community delete ".$name.";";
              break;
          }
        }
        // Next-hop
        foreach($set->getElementsByTagName('next-hop') as $n) {
          // Next-hop spec is mandatory
          $next_hop = $n->nodeValue;
          if(empty($next_hop))
            continue;
          switch($next_hop) {
            case 'self':
              $junos_conf[] = $pad."next-hop self;";
              break;
            case 'reject':
              $junos_conf[] = $pad."next-hop reject;";
              break;
            case 'discard':
              $junos_conf[] = $pad."next-hop discard;";
              break;
            case 'peer':
            case 'peeraddress':
            case 'peer-address':
            case 'peer_address':
              $junos_conf[] = $pad."next-hop peer-address;";
              break;
            default:
              $junos_conf[] = $pad."next-hop ".$next_hop.";";
              break;
          }
          break;
        }

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'junos', 'append');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // There can be only one <set> within <term>
        break;
      }

      // Add final action if defined
      $action = $term->getAttribute('action');
      if($action == "permit" || $action == "accept")
        $junos_conf[] = $pad."accept;";
      elseif($action == "deny" || $action == "reject")
        $junos_conf[] = $pad."reject;";

      $pad = str_pad('', --$depth*4);
      $junos_conf[] = $pad."}";

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'junos', 'append');
      if(!empty($ff))
        $junos_conf[] = $ff;

      // End term
      $pad = str_pad('', --$depth*4);
      $junos_conf[] = $pad."}";
    }

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'junos', 'append');
    if(!empty($ff))
      $junos_conf[] = $ff;

    // End policy statement
    $junos_conf[] = "}";
  }

  return true;
}

?>
