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

function policy_generate($template, &$iosxr_conf, &$include)
{
  foreach($template->getElementsByTagName('policy') as $policy) {
    // Policy name is mandatory
    $policy_name = $policy->getAttribute('id');
    if(!is_name($policy_name))
      continue;

    // Begin policy
    $iosxr_conf[] = "route-policy ".$policy_name;

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'iosxr', 'prepend');
    if(!empty($ff))
      $iosxr_conf[] = $ff;

    $if = "if";

    foreach($policy->getElementsByTagName('term') as $term) {

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'iosxr', 'prepend');
      if(!empty($ff))
        $iosxr_conf[] = $ff;

      // Match conditions
      $match_conf = array();

      foreach($term->getElementsByTagName('match') as $match) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'iosxr', 'prepend');
        if(!empty($ff))
          $match_conf[] = $ff;

        // Protocol
        $protocols = array();
        foreach($match->getElementsByTagName('protocol') as $p) {
          // Protocol name is mandatory
          $protocol_name = $p->nodeValue;
          // Routing process ID is mandatory for dynamic protocols
          $id = $p->getAttribute('id');
          // Template protocol names => IOS XR protocol names
          switch($protocol_name) {
            case 'local':
            case 'direct':
            case 'connected':
              $protocols[] = "connected";
              break;
            case 'aggregate':
            case 'static':
              $protocols[] = "static";
              break;
            case 'rip1':
            case 'rip2':
            case 'ripv1':
            case 'ripv2':
              if(is_numeric($id))
                $protocols[] = "rip ".$id;
              break;
            case 'ospf2':
            case 'ospfv2':
              if(is_numeric($id))
                $protocols[] = "ospf ".$id;
              break;
            case 'ospf3':
              if(is_numeric($id))
                $protocols[] = "ospfv3 ".$id;
              break;
            case 'bgp':
            case 'rip':
            case 'ospf':
            case 'ospfv3':
            case 'eigrp':
              if(is_numeric($id))
                $protocols[] = $protocol_name." ".$id;
              break;
            case 'isis':
              if(!empty($id))
                $protocols[] = $protocol_name." ".$id;
              break;
            default:
              continue 2;
          }
        }
        if(!empty($protocols))
          $match_conf[] = "protocol in ( ".implode(" , ", $protocols)." )";
        // Prefix list (prefix set)
        $prefix_sets = array();
        foreach($match->getElementsByTagName('prefix-list') as $p) {
          // Prefix set name is mandatory
          $prefix_set_name = $p->nodeValue;
          if(empty($prefix_set_name))
            continue;
          $prefix_sets[] = "destination in ".$prefix_set_name;
          // Include prefix set definition ?
          switch($p->getAttribute('include')) {
            case 'true':
            case 'yes':
            case 'on':
            case '1':
              // Add prefix set name to the inclusion list
              include_config($include, 'prefixlist', $prefix_set_name);
              break;
          }
        }
        if(!empty($prefix_sets))
          $match_conf[] = implode(" or\n".str_pad('', strlen($if)+5), $prefix_sets);
        // AS-path
        $aspaths = array();
        foreach($match->getElementsByTagName('as-path') as $a) {
          // AS-path name is mandatory
          $aspath = $a->nodeValue;
          if(!empty($aspath))
            $aspaths[] = "as-path in ".$aspath;
        }
        if(!empty($aspaths))
          $match_conf[] = implode(" or\n".str_pad('', strlen($if)+5), $aspaths);
        // Community
        $communities = array();
        foreach($match->getElementsByTagName('community') as $c) {
          // Community name is mandatory
          $community = $c->nodeValue;
          if(!empty($community))
            $communities[] = "community matches-any ".$community;
        }
        if(!empty($communities))
          $match_conf[] = implode(" or\n".str_pad('', strlen($if)+5), $communities);
        // Neighbor (advertising source of the route)
        $neighbors = array();
        foreach($match->getElementsByTagName('neighbor') as $n) {
          // Neighbor address is mandatory
          $neighbor = $n->nodeValue;
          if(!empty($neighbor))
            $neighbors[] = $neighbor;
        }
        if(!empty($neighbors))
          $match_conf[] = "source in ( ".implode(" , ", $neighbors)." )";

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'iosxr', 'append');
        if(!empty($ff))
          $match_conf[] = $ff;

        // There can be only one <match> within <term>
        break;
      }

      // Put together the RPL match line
      $iosxr_conf[] = empty($match_conf) ?
                        "  else":
                        "  ".$if." ( ".implode(" ) and\n".str_pad('', strlen($if)+2)." ( ", $match_conf)." ) then";

      foreach($term->getElementsByTagName('set') as $set) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'iosxr', 'prepend');
        if(!empty($ff))
          $iosxr_conf[] = $ff;

        // AS-path prepend
        foreach($set->getElementsByTagName('prepend') as $p) {
          // AS-path prepend string is mandatory
          $prepend = $p->nodeValue;
          if(!empty($prepend))
            $iosxr_conf[] = "    prepend as-path ".preg_replace('/\s+/', " . ", $prepend);
          break;
        }
        // Multi-exit discriminator (MED)
        foreach($set->getElementsByTagName('med') as $m) {
          // MED amount is mandatory
          $metric = $m->nodeValue;
          if(!is_numeric($metric))
            break;
          switch($p->getAttribute('action')) {
            case '+':
            case 'add':
              $iosxr_conf[] = "    set med + ".$metric;
              break;
            case '-':
            case 'sub':
            case 'subtract':
              $iosxr_conf[] = "    set med - ".$metric;
              break;
            default:
              $iosxr_conf[] = "    set med ".$metric;
              break;
          }
          // There can be only one MED
          break;
        }
        // Local preference
        foreach($set->getElementsByTagName('local-preference') as $l) {
          // Local preference amount is mandatory
          $preference = $l->nodeValue;
          if(is_numeric($preference))
            $iosxr_conf[] = "    set local-preference ".$preference;
          // There can be only one local preference
          break;
        }
        // Origin
        foreach($set->getElementsByTagName('origin') as $o) {
          // Origin spec is mandatory
          switch($o->nodeValue) {
            case 'i':
            case 'igp':
              $iosxr_conf[] = "    set origin igp";
              break;
            case 'e':
            case 'egp':
              $iosxr_conf[] = "    set origin egp";
              break;
            case '?':
            case 'incomplete':
              $iosxr_conf[] = "    set origin incomplete";
              break;
          }
          // There can be only one origin
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
              $iosxr_conf[] = "    set community ".$name;
              break;
            case '+':
            case 'add':
              $iosxr_conf[] = "    set community ".$name." additive";
              break;
            case '-':
            case 'delete':
              $iosxr_conf[] = "    delete community ".$name;
              break;
          }
        }
        // Next-hop
        foreach($set->getElementsByTagName('next-hop') as $n) {
          // Next-hop spec is mandatory
          $next_hop = $n->nodeValue;
          if(empty($next_hop))
            break;
          switch($next_hop) {
            case 'self':
              $iosxr_conf[] = "    set next-hop self";
              break;
            case 'reject':
            case 'discard':
              $iosxr_conf[] = "    set next-hop discard";
              break;
            case 'peer':
            case 'peeraddress':
            case 'peer-address':
            case 'peer_address':
              $iosxr_conf[] = "    set next-hop peer-address";
              break;
            default:
              $iosxr_conf[] = "    set next-hop ".$next_hop;
              break;
          }
          // There can be only one next-hop
          break;
        }

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'iosxr', 'append');
        if(!empty($ff))
          $iosxr_conf[] = $ff;

        // There can be only one <set> within <term>
        break;
      }

      // Add final action if defined
      $action = $term->getAttribute('action');
      if($action == "permit" || $action == "accept")
        $iosxr_conf[] = "    pass";
      elseif($action == "deny" || $action == "reject")
        $iosxr_conf[] = "    drop";

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'iosxr', 'append');
      if(!empty($ff))
        $iosxr_conf[] = $ff;

      // End term and prepare for the next
      $if = "elseif";
    }

    // End policy terms
    $iosxr_conf[] = "  endif";

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'iosxr', 'append');
    if(!empty($ff))
      $iosxr_conf[] = $ff;

    // End policy
    $iosxr_conf[] = "end-policy";
  }

  return true;
}

?>
