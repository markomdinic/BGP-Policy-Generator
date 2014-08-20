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

include_once $config['includes_dir'].'/platform/junosxsl/common.inc.php';

function policy_content_type()
{
  return junosxsl_content_type();
}

function policy_begin(&$junos_conf)
{
  return junosxsl_begin($junos_conf);
}

function policy_generate($template, &$junos_conf, &$include)
{
  foreach($template->getElementsByTagName('policy') as $policy) {
    // Policy name is mandatory
    $policy_name = $policy->getAttribute('id');
    if(empty($policy_name))
      continue;

    // Begin policy statement
    $junos_conf[] = "<policy-statement>";
    $junos_conf[] = "<name>".$policy_name."</name>";

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'junosxsl', 'prepend');
    if(!empty($ff))
      $junos_conf[] = $ff;

    foreach($policy->getElementsByTagName('term') as $term) {
      // Term name is mandatory
      $term_name = $term->getAttribute('id');
      if(empty($term_name))
        continue;

      // Begin term
      $junos_conf[] = "<term>";
      $junos_conf[] = "<name>".$term_name."</name>";

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'junosxsl', 'prepend');
      if(!empty($ff))
        $junos_conf[] = $ff;

      // Match conditions
      $junos_conf[] = "<from>";
      foreach($term->getElementsByTagName('match') as $match) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'junosxsl', 'prepend');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // Family
        foreach($match->getElementsByTagName('family') as $f) {
          // Family name is mandatory
          switch($f->nodeValue) {
            case 'inet':
            case 'ipv4':
              $junos_conf[] = "<family>inet</family>";
              break;
            case 'inet6':
            case 'ipv6':
              $junos_conf[] = "<family>inet6</family>";
              break;
            case 'iso':
              $junos_conf[] = "<family>iso</family>";
              break;
          }
          break;
        }
        // Protocol
        foreach($match->getElementsByTagName('protocol') as $p) {
          $proto = $p->nodeValue;
          switch($proto) {
            case 'connected':
              $junos_conf[] = "<protocol>direct</protocol>";
              break;
            case 'rip1':
            case 'rip2':
            case 'ripv1':
            case 'ripv2':
              $junos_conf[] = "<protocol>rip</protocol>";
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
              $junos_conf[] = "<protocol>".$proto."</protocol>";
              break;
          }
        }
        // Prefix list
        foreach($match->getElementsByTagName('prefix-list') as $p) {
          // Prefix list name is mandatory
          $prefix_list_name = $p->nodeValue;
          if(empty($prefix_list_name))
            continue;
          $junos_conf[] = "<prefix-list-filter>";
          $junos_conf[] = "<list_name>".$prefix_list_name."</list_name>";
          switch($p->getAttribute('match')) {
            case 'longer':
              $junos_conf[] = "<longer/>";
              break;
            case 'orlonger':
              $junos_conf[] = "<orlonger/>";
              break;
            default:
              $junos_conf[] = "<exact/>";
              break;
          }
          $junos_conf[] = "</prefix-list-filter>";
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
        foreach($match->getElementsByTagName('as-path') as $a) {
          // AS-path is mandatory
          $aspath = $a->nodeValue;
          if(!empty($aspath))
            $junos_conf[] = "<as-path>".$aspath."</as-path>";
        }
        // Community
        foreach($match->getElementsByTagName('community') as $c) {
          // Community name is mandatory
          $community = $c->nodeValue;
          if(!empty($community))
            $junos_conf[] = "<community>".$community."</community>";
        }
        // Neighbor
        foreach($match->getElementsByTagName('neighbor') as $n) {
          // Neighbor address is mandatory
          $neighbor = $n->nodeValue;
          if(!empty($neighbor))
            $junos_conf[] = "<neighbor>".$neighbor."</neighbor>";
        }

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($match, 'junosxsl', 'append');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // There can be only one <match? within <term>
        break;
      }
      $junos_conf[] = "</from>";

      // Set/change attributes
      $junos_conf[] = "<then>";
      foreach($term->getElementsByTagName('set') as $set) {

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'junosxsl', 'prepend');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // AS-path prepend
        foreach($set->getElementsByTagName('prepend') as $p) {
          // AS-path prepend string is mandatory
          $prepend = $p->nodeValue;
          if(!empty($prepend))
            $junos_conf[] = "<as-path-prepend>".$prepend."</as-path-prepend>";
          break;
        }
        // Multi-exit discriminator (MED)
        foreach($set->getElementsByTagName('med') as $m) {
          // MED amount is mandatory
          $metric = $m->nodeValue;
          if(is_numeric($metric))
            $junos_conf[] = "<metric>".$metric."</metric>";
          break;
        }
        // Protocol preference (administrative distance)
        foreach($set->getElementsByTagName('protocol-preference') as $p) {
          // Preference amount is mandatory
          $preference = $p->nodeValue;
          if(!is_numeric($preference))
            continue;
          $junos_conf[] = "<preference>";
          switch($p->getAttribute('action')) {
            case '+':
            case 'add':
              $junos_conf[] = "<add>".$preference."</add>";
              break;
            case '-':
            case 'sub':
            case 'subtract':
              $junos_conf[] = "<subtract>".$preference."</subtract>";
              break;
            default:
              $junos_conf[] = "<preference>".$preference."</preference>";
              break;
          }
          $junos_conf[] = "</preference>";
          break;
        }
        // Local preference
        foreach($set->getElementsByTagName('local-preference') as $l) {
          // Local preference amount is mandatory
          $preference = $l->nodeValue;
          if(!is_numeric($preference))
            continue;
          $junos_conf[] = "<local-preference>";
          switch($l->getAttribute('action')) {
            case '+':
            case 'add':
              $junos_conf[] = "<add>".$preference."</add>";
              break;
            case '-':
            case 'sub':
            case 'subtract':
              $junos_conf[] = "<subtract>".$preference."</subtract>";
              break;
            default:
              $junos_conf[] = "<local-preference>".$preference."</local-preference>";
              break;
          }
          $junos_conf[] = "</local-preference>";
          break;
        }
        // Origin
        foreach($set->getElementsByTagName('origin') as $o) {
          // Origin spec is mandatory
          switch($o->nodeValue) {
            case 'i':
            case 'igp':
              $junos_conf[] = "<origin>igp</origin>";
              break;
            case 'e':
            case 'egp':
              $junos_conf[] = "<origin>egp</origin>";
              break;
            case '?':
            case 'incomplete':
              $junos_conf[] = "<origin>incomplete</origin>";
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
          $junos_conf[] = "<community>";
          $junos_conf[] = "<community-name>".$name."</community-name>";
          switch($action) {
            case '=':
            case 'set':
              $junos_conf[] = "<set/>";
              break;
            case '+':
            case 'add':
              $junos_conf[] = "<add/>";
              break;
            case '-':
            case 'delete':
              $junos_conf[] = "<delete/>";
              break;
          }
          $junos_conf[] = "</community>";
        }
        // Next-hop
        foreach($set->getElementsByTagName('next-hop') as $n) {
          // Next-hop spec is mandatory
          $next_hop = $n->nodeValue;
          if(empty($next_hop))
            continue;
          $junos_conf[] = "<next-hop>";
          switch($next_hop) {
            case 'self':
              $junos_conf[] = "<self/>";
              break;
            case 'reject':
              $junos_conf[] = "<reject/>";
              break;
            case 'discard':
              $junos_conf[] = "<discard/>";
              break;
            case 'peer':
            case 'peeraddress':
            case 'peer-address':
            case 'peer_address':
              $junos_conf[] = "<peer-address/>";
              break;
            default:
              $junos_conf[] = "<address>".$next_hop."</address>";
              break;
          }
          $junos_conf[] = "</next-hop>";
          break;
        }

        // Add final action if defined
        $action = $term->getAttribute('action');
        if($action == "permit" || $action == "accept")
          $junos_conf[] = "<accept/>";
        elseif($action == "deny" || $action == "reject")
          $junos_conf[] = "<reject/>";

        // Look for 'config' tags that contain
        // free-form, device-specific config
        $ff = get_freeform_config($set, 'junosxsl', 'append');
        if(!empty($ff))
          $junos_conf[] = $ff;

        // There can be only one <set> within <term>
        break;
      }
      $junos_conf[] = "</then>";

      // Look for 'config' tags that contain
      // free-form, device-specific config
      $ff = get_freeform_config($term, 'junosxsl', 'append');
      if(!empty($ff))
        $junos_conf[] = $ff;

      // End term
      $junos_conf[] = "</term>";
    }

    // Look for 'config' tags that contain
    // free-form, device-specific config
    $ff = get_freeform_config($policy, 'junosxsl', 'append');
    if(!empty($ff))
      $junos_conf[] = $ff;

    // End policy statement
    $junos_conf[] = "</policy-statement>";
  }

  return true;
}

function policy_end(&$junos_conf)
{
  return junosxsl_end($junos_conf);
}

?>
