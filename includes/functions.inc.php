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

include_once $config['includes_dir'].'/tools.inc.php';
include_once $config['includes_dir'].'/whois.inc.php';
include_once $config['includes_dir'].'/vcs.inc.php';

// **************************** TEMPLATE FUNCTIONS ****************************

function load_template($filename)
{
  // Input params sanity check
  if(empty($filename) || !is_file($filename))
    return;

  $doc = new DomDocument;
  $doc->preserveWhiteSpace = false;
  $doc->validateOnParse = true;
  $doc->load($filename);

  return $doc;
}

function load_templates($dirname)
{
  // Parameters must be sane
  if(empty($dirname) || !is_dir($dirname))
    return false;

  // Prepare for directory enumeration
  $dir = opendir($dirname);
  if(!isset($dir))
    return false;

  $templates = array();

  // Enumerate template files in the directory
  while(($filename = readdir($dir)) !== FALSE) {
    // Skip dot files (including '.' and '..')
    if(preg_match('/^\./', $filename))
      continue;
    // Load template file
    $template = load_template($dirname.'/'.$filename);
    if(isset($template))
      // Store template in the array
      $templates[$filename] = $template;
  }

  // Finish directory enumeration
  closedir($dir);

  return $templates;
}

function find_template_by_value($type, $tag, $value)
{
  global $config;

  // Don't waste my time
  if(empty($type) || empty($tag) || empty($value))
    return;

  $values = is_array($value) ? $value:array($value);
  $results = array();

  // Load all templates in the directory and search them
  foreach(load_templates($config['templates_dir'].'/'.$type) as $filename => $template) {
    // Examine only a specific tag type
    foreach($template->getElementsByTagName($tag) as $node) {
      // Get node's value
      $node_val = $node->nodeValue;
      // If node's value matches the search criteria ...
      if(isset($node_val) && array_search($node_val, $values) !== FALSE) {
        // ... store found element
        $results[] = $node->parentNode;
        // If we have the number of results,
        // matching the number of search values ...
        if(count($results) >= count($values))
          // ... stop searching
          break 2;
      }
    }
  }

  // If single value was given, return a single result
  // otherwise, return the array of results
  if(count($results))
    return (count($values) == 1) ? $results[0]:$results;
}

function find_template_by_attr($type, $tag, $attr, $attrval)
{
  global $config;

  // Don't waste my time
  if(empty($type) || empty($tag) || 
     empty($attr) || empty($attrval))
    return;

  $attrvals = is_array($attrval) ? $attrval:array($attrval);
  $results = array();

  // Load all templates in the directory and search them
  foreach(load_templates($config['templates_dir'].'/'.$type) as $filename => $template) {
    // Examine only a specific tag type
    foreach($template->getElementsByTagName($tag) as $node) {
      // Get node's attribute's value
      $node_attrval = $node->getAttribute($attr);
      // If node's attribute's value matches the search criteria ...
      if(!empty($node_attrval) && array_search($node_attrval, $attrvals) !== FALSE) {
        // ... store found element
        $results[] = $node->parentNode;
        // If we have the number of results,
        // matching the number of search values ...
        if(count($results) >= count($attrvals))
          // ... stop searching
          break 2;
      }
    }
  }

  // If single value was given, return a single result
  // otherwise, return the array of results
  if(count($results))
    return (count($attrvals) == 1) ? $results[0]:$results;
}

function update_template($autotemplate, &$statusmsg="")
{
  global $config;

  // Don't waste time if template or local ASN is missing
  if(empty($autotemplate) || empty($config['local_as']))
    return;

  // Extract our ASN
  if(!preg_match('/^(?:AS)?(\d+)$/i', $config['local_as'], $m))
    return;

  // Make sure it is always in numeric format
  $local_as = $m[1];

  // This array will receive policies
  // built as strings in XML format
  $template_elements = array();

  // Process all policies in this autopolicy template
  foreach($autotemplate->getElementsByTagName('policy') as $policy) {

    // Policy ID (name) is mandatory
    $policy_id = $policy->getAttribute('id');
    // If policy name is missing or invalid,
    // skip to the next policy
    if(!is_name($policy_id))
      continue;

    // Peer's AS number is mandatory
    $peer_as = $policy->getAttribute('peer-as');
    if(empty($peer_as) || !preg_match('/^(?:AS)?(\d+)$/i', $peer_as, $m))
      return;

    // Make sure peer's ASN is always in AS<n> format
    $peer_as = $m[1];

    // Use global whois servers by default
    $whois_servers = NULL;

    // Process per-policy whois server configuration
    foreach($policy->getElementsByTagName('whois') as $whois) {

      // Start a new list of per-policy whois servers
      $server_list = array();

      // Process whois servers parameters
      foreach($whois->getElementsByTagName('server') as $server) {

        // Start a new server parameters block
        $whois_server = array();

        // Whois server address is mandatory
        $whois_host = $server->nodeValue;
        if(empty($whois_host)) {
          status_message("Autopolicy template ".$policy_id." has a misconfigured whois server.", $statusmsg);
          continue;
        }
        $whois_server['server'] = $whois_host;

        // Whois server port is optional
        $whois_port = $server->getAttribute('port');
        if(!empty($whois_port)) {
          if(!is_port($whois_port)) {
            status_message("Autopolicy template ".$policy_id." defines a whois server ".$whois_host." with invalid port \"".$whois_port."\".", $statusmsg);
            // Try the next server
            continue;
          }
          $whois_server['port'] = $whois_port;
        }

        // Whois address family is optional
        $whois_family = $server->getAttribute('family');
        if(!empty($whois_family))
          $whois_server['family'] = $whois_family;

        // Whois server type is optional
        $whois_type = $server->getAttribute('type');
        if(!empty($whois_type))
          $whois_server['type'] = $whois_type;

        // Whois source is optional
        $whois_source = $server->getAttribute('source');
        if(!empty($whois_source))
          $whois_server['source'] = $whois_source;

        // Whois server socket timeout is optional
        $whois_sock_timeout = $server->getAttribute('sock-timeout');
        if(!empty($whois_sock_timeout)) {
          if(!is_positive($whois_sock_timeout)) {
            status_message("Autopolicy template ".$policy_id." defines a whois server ".$whois_host." with invalid socket timeout \"".$whois_sock_timeout."\" !", $statusmsg);
            // Try the next server
            continue;
          }
          $whois_server['sock_timeout'] = $whois_sock_timeout;
        }

        // Whois server query timeout is optional
        $whois_query_timeout = $server->getAttribute('query-timeout');
        if(!empty($whois_query_timeout)) {
          if(!is_positive($whois_query_timeout)) {
            status_message("Autopolicy template ".$policy_id." defines a whois server ".$whois_host." with invalid query timeout \"".$whois_query_timeout."\" !", $statusmsg);
            // Try the next server
            continue;
          }
          $whois_server['query_timeout'] = $whois_query_timeout;
        }

        // Whois query size (number of RPSL objects per query) is optional
        $whois_query_size = $server->getAttribute('query-size');
        if(!empty($whois_query_size)) {
          if(!is_positive($whois_query_size)) {
            status_message("Autopolicy template ".$policy_id." defines a whois server ".$whois_host." with invalid query size \"".$whois_query_size."\" !", $statusmsg);
            // Try the next server
            continue;
          }
          $whois_server['query_size'] = $whois_query_size;
        }

        // Add whois server parameters to the per-policy server list
        $server_list[] = $whois_server;
      }

      // If we have at least one whois server in the list ...
      if(!empty($server_list))
        // ... use per-policy whois servers
        $whois_servers = $server_list;

      // There can be only one servers section
      break;
    }

    status_message("Autopolicy template ".$policy_id." is using ".(empty($whois_servers) ? "global":"per-policy")." whois servers.", $statusmsg);

    // This optional attribute, if set to "yes",
    // forces whois code to consider valid only
    // those prefixes that have at least one valid
    // path between local AS and prefix's origin.
    //
    // Valid path is an unbroken chain of aut-num
    // objects between local AS and origin AS,
    // linked using import/export attributes.
    //
    // Chain remains unbroken if every AS along
    // the path is importing at least a portion of
    // whatever it's upstream AS is exporting.
    switch($policy->getAttribute('validate-paths')) {
      case 'true':
      case 'yes':
      case 'on':
      case '1':
        $validate_as_paths = true;
        break;
      default:
        $validate_as_paths = false;
        break;
    }

    // If autopolicy terms below contain auto-as-path tags,
    // we must search for as-path information as well
    $include_as_paths = $policy->getElementsByTagName('auto-as-path')->length > 0;

    // To which protocol family should prefixes belong ?
    $family = $policy->getAttribute('family');
    switch($family) {
      case 'inet':
        $address_family = AF_INET;
        break;
      case 'inet6':
        $address_family = AF_INET6;
        break;
      default:
        // Next policy
        continue 2;
    }

    status_message("Fetching af ".$family." prefixes announced by AS".$peer_as." to AS".$local_as." ...", $statusmsg);

    // Get prefixes and/or AS paths announced by <peer-as> to <local-as>
    $announced = get_announced_prefixes('AS'.$peer_as,
                                        'AS'.$local_as,
                                        $address_family,
                                        $include_as_paths,
                                        $validate_as_paths,
                                        $whois_servers);

    // No point going any further
    // if prefixes are missing
    if(empty($announced)) {
      status_message("Got no af ".$family." prefixes from AS".$peer_as.".", $statusmsg);
      return;
    }

    $status_message = "AS".$peer_as." is announcing (af ".$family.") ".count(array_keys($announced['prefixes']))." autonomous systems";

    if(isset($announced['prefixes']))
      $status_message .= ", ".array_sum(array_map('count', $announced['prefixes']))." prefixes";

    if(isset($announced['as_paths']))
      $status_message .= ", ".array_sum(array_map('count', $announced['as_paths']))." AS paths";

    status_message($status_message.".", $statusmsg);

    // This array will receive terms
    // built as strings in XML format
    $policy_elements = array();

    // Process all terms within current policy
    foreach($policy->getElementsByTagName('term') as $term) {

      // Term ID (name) is mandatory
      $term_id = $term->getAttribute('id');
      // If term name is missing or invalid,
      // skip to the next policy
      if(!is_name($term_id))
        continue 2;

      // Term action is mandatory
      switch($term->getAttribute('action')) {
        case 'permit':
          $term_action = "permit";
          break;
        case 'deny':
          $term_action = "deny";
          break;
        // Next policy
        default:
          continue 3;
      }

      // This optional attribute, if set to "yes",
      // tells us to ignore missing term sections
      // and allow empty terms unconditionally
      switch($term->getAttribute('ignore-missing')) {
        case 'true':
        case 'yes':
        case 'on':
        case '1':
          $term_ignore_missing = true;
          break;
        default:
          $term_ignore_missing = false;
          break;
      }

      // This variable will hold the number
      // of <auto-prefix-list> tags specified
      // within this term's <match> element
      $auto_prefix_list_count = 0;

      // This array will receive match and set
      // elements built as strings in XML format
      $term_elements = array();

      // Process match element inside current term
      foreach($term->getElementsByTagName('match') as $match) {

        // This optional attribute, if set to "yes",
        // tells us to ignore missing match conditions
        // even if that changes the term's semantics
        switch($match->getAttribute('ignore-missing')) {
          case 'true':
          case 'yes':
          case 'on':
          case '1':
            $match_ignore_missing = true;
            break;
          default:
            $match_ignore_missing = false;
            break;
        }

        // This array will receive prefix list tags
        // built as strings in XML format
        $match_elements = array();

        // Process all prefix list tags inside match element
        $prefix_lists = $match->getElementsByTagName('auto-prefix-list');
        foreach($prefix_lists as $p) {

          // Get the match type, if defined
          switch($p->getAttribute('match')) {
            case 'longer':
              $match_type = "longer";
              break;
            case 'orlonger':
              $match_type = "orlonger";
              break;
            default:
              $match_type = "exact";
              break;
          }

          // Get the include flag, if defined.
          // It will be copied to generated
          // <prefix-list> tags, thus it is
          // not a boolean flag, but a string.
          switch($p->getAttribute('include')) {
            case 'true':
            case 'yes':
            case 'on':
            case '1':
              $include_flag = "yes";
              break;
            default:
              $include_flag = "no";
              break;
          }

          // Maximum prefix length is optional
          $upto = $p->getAttribute('upto');
          if(is_numeric($upto)) {
            switch($family) {
              case 'inet':
                if($upto < 0 || $upto > 32)
                  unset($upto);
                break;
              case 'inet6':
                if($upto < 0 || $upto > 128)
                  unset($upto);
                break;
              default:
                // Next policy
                continue 5;
            }
          }

          // This mandatory attribute defines a regular expression
          // used to select prefixes automatically collected from
          // whois server by their origin AS. Auto prefix list tag
          // expands into a series of prefix lists selected by this
          // regular expression.
          $origin_regex = $p->getAttribute('origin');
          if(empty($origin_regex))
            continue;

          // This optional attribute, if defined and set to 'yes'
          // anables per-prefix-list prefix aggregation. By default
          // aggregation is disabled
          switch($p->getAttribute('aggregate')) {
            case 'true':
            case 'full':
            case 'all':
            case 'yes':
            case 'on':
            case '1':
              $aggregation = true;
              break;
            case 'overlapping':
            case 'longer':
              $aggregation = false;
              break;
            default:
              unset($aggregation);
              break;
          }

          // This optional attribute, if defined, represents regex
          // that directly filters prefixes automatically collected
          // from whois server.
          $prefix_regex = $p->getAttribute('filter');

          // Tag's value is optional and, if defined, represents
          // string to prepend to auto-generated prefix list name.
          $name_prepend = is_name($p->nodeValue) ? ($p->nodeValue).'-':'';

          // Sort prefixes by ASn
          ksort($announced['prefixes'], SORT_NATURAL);

          // Loop through all collected routing data
          foreach($announced['prefixes'] as $origin_as => $prefixes) {

            // Without prefixes we have nothing to do
//            if(!isset($as_data['prefixes']))
//              continue;

            // Prefixes originated by this AS
//            $prefixes = $as_data['prefixes'];

            // AS paths from local AS to this AS
            if(isset($announced['as_paths'][$origin_as]))
              $as_paths = $announced['as_paths'][$origin_as];

            // Extract AS number from ASN
            if(!preg_match('/^(?:AS)?(\d+)$/i', $origin_as, $m))
              continue;

            $origin_as = $m[1];

            // Skip if current ASN doesn't match
            if(!preg_match('/'.$origin_regex.'/', $origin_as))
              continue;

            // Prefix list name is [<prepend>-]AF-<af>-AS<n>
            $prefix_list_name = $name_prepend.'AF-'.strtoupper($family).'-AS'.$origin_as;

            $prefix_list_items = array();

            // If aggregation is enabled ...
            if(isset($aggregation)) {
              switch($family) {
                case 'inet':
                  // ... aggregate IPv4 prefixes
                  $prefixes = aggregate_ipv4($prefixes, $aggregation);
                  if(empty($prefixes))
                    continue 2;
                  break;
                case 'inet6':
                  break;
                default:
                  // Next policy
                  continue 6;
              }
            }

            // Sort prefixes
            sort($prefixes, SORT_NATURAL);

            // Add prefixes to the prefix list
            foreach($prefixes as $prefix) {
              // If maximum prefix length is defined, prefixes must be
              // shorter or equal to the maximum prefix length
              if(isset($upto) && preg_match('/\/(\d+)$/', $prefix, $m) && $m[1] > $upto)
                continue;
              // If filter regex is defined, filter out prefixes not matching it
              if(empty($prefix_regex) || preg_match('/'.$prefix_regex.'/', $prefix))
                $prefix_list_items[] = "<item".(empty($upto) ? "":" upto=\"".$upto."\"").">".$prefix."</item>";
            }

            // If prefix list has no items ...
            if(count($prefix_list_items) < 1)
              // .. do not update it
              continue;

            // Begin prefix list template
            $prefix_list = "<?xml version=\"1.0\" standalone=\"yes\"?>\n";
            $prefix_list .= "<prefix-lists>\n";
            $prefix_list .= "<prefix-list id=\"".$prefix_list_name."\" family=\"".$family."\" origin=\"".$origin_as."\">\n";
            // Insert prefix list items
            $prefix_list .= implode("\n", $prefix_list_items)."\n";
            // End prefix list template
            $prefix_list .= "</prefix-list>\n";
            $prefix_list .= "</prefix-lists>\n";

            // Convert template to DOM
            $doc = new DomDocument;
            $doc->preserveWhiteSpace = false;
            $doc->validateOnParse = true;
            // Load prefix list template as a string
            // and parse it into DOM document
            $doc->loadXML($prefix_list);
            // Make XML output properly formatted
            $doc->formatOutput = true;
            // Write verified and properly formatted
            // template to the prefix lists directory
            $num = $doc->save($config['templates_dir'].'/prefixlist/'.$prefix_list_name);
            if($num === FALSE) {
              // Abort at the first sign of trouble
              status_message("Aborting: failed to write prefix list file ".$prefix_list_name.".", $statusmsg);
              return;
            }

            // Add tag to the match element
            // in the policy template
            $match_elements[] = "<prefix-list match=\"".$match_type."\" include=\"".$include_flag."\">".$prefix_list_name."</prefix-list>\n";
          }

        }

        // Get the number of <auto-prefix-list> tags
        // contained inside current <match> element
        $auto_prefix_list_count = $prefix_lists->length;

        // Copy the rest of match conditions unless <match>
        // contains <auto-prefix-list> tags that produced
        // no prefix lists, thus making the <match> section
        // invalid, or if explicitly told to ignore missing
        // match conditions
        if($match_ignore_missing ||
           $auto_prefix_list_count < 1 ||
           count($match_elements) > 0) {
          // Begin match element in the policy template
          $term_elements[] = "<match>";
          // If match conditions are present,
          // add them to the term element
          foreach($match->childNodes as $tag) {
            // Tag name must be known
            $tag_name = $tag->nodeName;
            // Skip comments, ignore auto-prefix-list tags
            if(empty($tag_name) || $tag_name == '#comment' || $tag_name == 'auto-prefix-list')
              continue;
            // Tag value must exist ...
            $tag_value = $tag->nodeValue;
            // ... even if it is an empty string
            if(empty($tag_value))
              $tag_value = "";
            $attrs = array();
            // Get all match condition's attributes
            if($tag->hasAttributes()) {
              foreach($tag->attributes as $attr => $attrval) {
                $val = $attrval->nodeValue;
                if(!empty($val))
                  $attrs[] = $attr."=\"".$val."\"";
              }
            }
            // Add tag to the match element in the policy template
            $term_elements[] = "<".$tag_name.(count($attrs) > 0 ? " ".implode(" ", $attrs):"").">".$tag_value."</".$tag_name.">";
          }
          // Add generated prefix list tags to the policy template
          $term_elements[] = implode("\n", $match_elements);
          // Close match element in the policy template
          $term_elements[] = "</match>";
        }
        // There can be only one match element
        break;
      }

      // Process set element inside current term
      foreach($term->getElementsByTagName('set') as $set) {
        // This optional attribute, if set to "yes",
        // tells us to ignore the missing match section
        // and create the set section unconditionally
        switch($set->getAttribute('ignore-missing')) {
          case 'true':
          case 'yes':
          case 'on':
          case '1':
            $set_ignore_missing = true;
            break;
          default:
            $set_ignore_missing = false;
            break;
        }
        // Copy all set statements unless <match> contains
        // <auto-prefix-list> tags that produced no prefix
        // lists, thus making the <match> section invalid
        // and, in turn, the entire <term>, which makes
        // the set section unneccessary, unless explicitly
        // configured to ignore the missing match section
        if($set_ignore_missing ||
           $auto_prefix_list_count < 1 ||
           count($term_elements) > 0) {
          // Begin set element in the policy template
          $term_elements[] = "<set>";
          // Copy all set statements within the set element
          foreach($set->childNodes as $tag) {
            // Tag name must be known
            $tag_name = $tag->nodeName;
            // Skip comments
            if(empty($tag_name) || $tag_name == '#comment')
              continue;
            // Tag value must exist ...
            $tag_value = $tag->nodeValue;
            // ... even if it is an empty string
            if(empty($tag_value))
              $tag_value = "";
            $attrs = array();
            // Build all set statement's attributes
            if($tag->hasAttributes()) {
              foreach($tag->attributes as $attr => $attrval) {
                $val = $attrval->nodeValue;
                if(!empty($val))
                  $attrs[] = $attr."=\"".$val."\"";
              }
            }
            // Add tag to the set element in the policy template
            $term_elements[] = "<".$tag_name.(count($attrs) > 0 ? " ".implode(" ", $attrs):"").">".$tag_value."</".$tag_name.">";
          }
          // Close set element in the policy template
          $term_elements[] = "</set>";
        }
        // There can be only one set element
        break;
      }

      // Empty term must not contain failed <auto-prefix-list> tags
      // if term action is 'permit'. It's safer to be conservative
      // here, because 'permit' term without match conditions usually
      // implicitly permits everything, so if we are missing a match
      // section because <auto-prefix-list> failed to produce match
      // conditions, we don't want to let everything in, considering
      // it might unintentionally accept full BGP feed from an unwanted
      // source and mess up our routing. If the match section contains
      // match conditions other than those specified by the failed
      // <auto-prefix-list> tag, the term with less match conditions
      // will match less and, in turn, 'permit' action will pass less
      // through, which may not be what we intended, but it is safer.
      //
      // On the other hand, if term action is 'deny', missing match
      // section will usually implicitly deny everything, which also
      // may not be what we intended, but it's still safer.
      //
      // By default, we will be conservative, thus allowing empty terms
      // only if they were configured that way by hand or term action is
      // set to 'deny'. To change that behavior, we use term attribute
      // ignore-missing, which will explicitly allow empty terms even
      // if term action is set to 'permit' and match section is missing
      // for whatever reason.

      // If term is not empty ...
      if(count($term_elements) > 0) {
        // ... add it to the policy
        $policy_elements[] = "<term id=\"".$term_id."\" action=\"".$term_action."\">";
        $policy_elements[] = implode("\n", $term_elements);
        $policy_elements[] = "</term>";
      // If empty term is configured to ignore missing sections,
      // or it contains no failed <auto-prefix-list> tags,
      // or term action is 'deny', it is generally ok, so ...
      } elseif($term_ignore_missing ||
               $auto_prefix_list_count < 1 ||
               $term_action == "deny")
        // ... add term specifying only the action
        $policy_elements[] = "<term id=\"".$term_id."\" action=\"".$term_action."\"/>";

    }

    // If policy is not empty ...
    if(count($policy_elements) > 0) {
      // ... add it to the policy template
      $template_elements[] = "<policy id=\"".$policy_id."\" peer-as=\"".$peer_as."\" family=\"".$family."\">";
      $template_elements[] = implode("\n", $policy_elements);
      $template_elements[] = "</policy>";
    }

  }

  // If at least one policy was generated ...
  if(count($template_elements) > 0) {
    // Assemble the complete policy template
    $template  = "<?xml version=\"1.0\" standalone=\"yes\"?>\n";
    $template .= "<policies>\n";
    $template .= implode("\n", $template_elements);
    $template .= "</policies>\n";
    // Convert template to DOM
    $doc = new DomDocument;
    $doc->preserveWhiteSpace = false;
    $doc->validateOnParse = true;
    // Load template as string
    // and parse it into DOM
    $doc->loadXML($template);
    // Return generated policy template
    return $doc;
  }

  // Otherwise, we failed
  return;
}

function update_template_by_id($id, &$log='')
{
  global $config;

  // Don't waste my time
  if(empty($id))
    return false;

  if(php_sapi_name() != "cli")
    header('Content-Type: ', 'text/plain');

  // Make sure this is always array
  $ids = is_array($id) ? $id:array($id);

  foreach($ids as $id) {
    status_message("Updating autopolicy template ".$id." ...", $log);

    // Load specific autopolicy template
    $autotemplate = load_template($config['templates_dir'].'/autopolicy/'.$id);
    if(!isset($autotemplate)) {
      status_message("Autopolicy template ".$id." not found.", $log);
      continue;
    }

    // Update operations' start time
    $start_time = microtime(true);
    // Generate config templates from autopolicy template
    $template = update_template($autotemplate, $log);
    // Calculate the duration of the update
    // (in seconds), rounded to 2 decimals
    $duration = round(microtime(true) - $start_time, 2);

    // If template update failed ...
    if(!isset($template)) {
      status_message("Autopolicy ".$id." update failed after ".$duration." seconds.", $log);
      // ... move on to the next template
      continue;
    }

    // Make XML output properly formatted
    $template->formatOutput = true;
    // Save updated template to the policy directory
    $template->save($config['templates_dir'].'/policy/'.$id);

    status_message("Autopolicy ".$id." successfully updated after ".$duration." seconds.", $log);
  }

  return true;
}

function update_all_templates(&$log='')
{
  global $config;

  if(php_sapi_name() != "cli")
    header('Content-Type: ', 'text/plain');

  // Load all autopolicy templates
  $autotemplates = load_templates($config['templates_dir'].'/autopolicy');
  if(empty($autotemplates)) {
    echo("No autopolicy templates defined.\n");
    return false;
  }

  status_message("Updating all autopolicy templates ...", $log);

  // Process all autopolicy template files
  foreach($autotemplates as $filename => $autotemplate) {
    // Update operations' start time
    $start_time = microtime(true);
    // Update template from autopolicy template
    $template = update_template($autotemplate, $log);
    // Calculate the duration of the update
    // (in seconds), rounded to 2 decimals
    $duration = round(microtime(true) - $start_time, 2);

    // If template update failed ...
    if(!isset($template)) {
      status_message("Autopolicy update failed after ".$duration." seconds.", $log);
      // ... move on to the next template
      continue;
    }

    // Make XML output properly formatted
    $template->formatOutput = true;
    // Save updated template to the policy directory
    $template->save($config['templates_dir'].'/policy/'.$filename);

    status_message("Autopolicy successfully updated after ".$duration." seconds.", $log);
  }

  return true;
}

function update_templates($id=NULL)
{
  global $config;

  // Drop root privileges and change
  // to http daemon's user/group
  drop_privileges();

  // Split comma-separated list of template IDs
  $ids = empty($id) ? array():explode(',', $id);

  // Initialize GIT repository (if neccessary)
  vcs_init_repository($config['templates_dir']);

  $log = '';

  $start_time = microtime(true);

  // Update autopolicies
  $res = empty($ids) ?
            update_all_templates($log):
            update_template_by_id($ids, $log);

  // Calculate the duration of the update
  // (in seconds), rounded to 2 decimals
  $duration = round(microtime(true) - $start_time, 2);

  // If update was successful ..
  if($res) {
    // ... commit changes in the repository
    vcs_commit($config['templates_dir'], $log);
    status_message("Done after ".$duration." seconds in total.", $log);
  // Otherwise ...
  } else {
    // ... reset to last good commit
    vcs_reset();
    status_message("Failed after ".$duration." seconds in total.", $log);
  }

  return $res;
}

// ************************** PREFIX-LIST FUNCTIONS ***************************

function find_prefixlist_by_id($id)
{
  return find_template_by_attr('prefixlist', 'prefix-list', 'id', $id);
}

function find_prefixlist_by_origin($origin)
{
  return find_template_by_attr('prefixlist', 'prefix-list', 'origin', $origin);
}

// ***************************** POLICY FUNCTIONS *****************************

function find_policy_by_id($id)
{
  return find_template_by_attr('policy', 'policy', 'id', $id);
}

function find_policy_by_peer_as($peer_as)
{
  return find_template_by_attr('policy', 'policy', 'peer-as', $peer_as);
}

// *************************** GENERATOR FUNCTIONS ****************************

function include_config(&$include, $type, $id)
{
  if(!isset($include) || empty($type) || empty($id))
    return;

  $include[$type][] = $id;
}

function format_generated_config($platform, &$device_conf)
{
  // Nothing to do ?
  if(empty($device_conf))
    return;

  // Optional function that returns
  // device configuration in platform
  // specific format and matching
  // content type
  $formatter = $platform.'_format';
  if(is_callable($formatter))
    // Call platform-specific formatter
    // to prepare configuration for output
    list($conf_text, $content_type) = $formatter($device_conf);
  // Otherwise ...
  else
    // ... just serialize configuration
    $conf_text = implode("\n", $device_conf)."\n";

  // Default content type is text/plain
  if(empty($content_type))
    $content_type = "text/plain";

  return array($conf_text, $content_type);
}

function print_generated_config($formatted_conf)
{
  // Nothing to do ?
  if(empty($formatted_conf))
    return;

  list($conf_text, $content_type) = $formatted_conf;
  if(empty($conf_text) || empty($content_type))
    return;

  // Generate HTTP headers if not called from CLI
  if(!(php_sapi_name() == 'cli')) {
    header('Content-Type: '.$content_type);
    header('Content-Length: '.strlen($conf_text));
  }

  // Dump generated configuration
  echo($conf_text);
}

function generate_config_by_id($platform, $type, $ids, &$device_conf=array())
{
  global $config;

  // Need these parameters
  if(empty($platform) || empty($type) ||
     empty($ids) || !isset($device_conf))
    return false;

  // Format path to generator code for type-specific config elements
  $include_generator = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  // This code is mandatory
  if(!is_file($include_generator))
    return false;

  // Find the requested template by id
  $find_by_id = 'find_'.$type.'_by_id';
  $element = $find_by_id($ids);
  if(!isset($element))
    return false;

  // Format path to generator code for common config elements
  $include_common = $config['includes_dir'].'/platform/'.$platform.'/common.inc.php';
  // Common code is optional
  if(is_file($include_common))
    // If file exists - include it
    include_once $include_common;

  // Include generator code
  include_once $include_generator;

  // Device-specific begin/end generators
  // should be called if we are starting
  // with an empty configuration
  $fresh = empty($device_conf) ? true:false;

  // Code to execute before generator,
  // possibly to prepare config headers,
  // but only if we are starting fresh
  if($fresh) {
    // Optional common config header
    $common_begin = $platform.'_begin';
    if(is_callable($common_begin))
      $common_begin($device_conf);
    // Optional type-specific section header
    $section_begin = $type.'_begin';
    if(is_callable($section_begin))
      $section_begin($device_conf);
  }

  // This array will contain
  // configuration to include
  $include = array();

  // This is the selection of elements
  // to be used for config generation
  $elements = is_array($element) ? $element:array($element);
  // This is our type-specific generator name
  $generate = $type.'_generate';
  // Generate configuration for selected element(s)
  foreach($elements as $element) {
    // Invoke type-specific generator
    if($generate($element, $device_conf, $include) === FALSE)
      // Generators return explicit FALSE on error,
      return false;
  }

  // Additional config requested by processed templates,
  // if generator used for processing supports it.
  //
  // WARNING! This can lead to inclusion loops if generators
  // allow mutual inclusion of config types. This should NEVER
  // happen. Inclusion should always be allowed in one-way only.
  // More complex structures include less complex ones, NEVER
  // the other way around. Developers, you have been warned!
  if(generate_included_config($platform, $device_conf, $include) === FALSE)
    return false;

  // Code to execute after generator,
  // possibly to create config footer,
  // but only if we started fresh
  if($fresh) {
    // Optional type-specific section footer
    $section_end = $type.'_end';
    if(is_callable($section_end))
      $section_end($device_conf);
    // Optional common config footer
    $common_end = $platform.'_end';
    if(is_callable($common_end))
      $common_end($device_conf);
  }

  // If external config storage wasn't given ...
  if(func_num_args() < 4)
    // ... return generated configuration
    // in the platform-specific format
    return format_generated_config($platform, $device_conf);

  // Success
  return true;
}

function generate_included_config($platform, &$device_conf, &$include)
{
  // Nothing to do without input data
  if(empty($platform) || !isset($device_conf) || !isset($include))
    return false;

  foreach($include as $type => $ids) {
    if(!is_array($ids))
      continue;
    // Weed out duplicates
    $ids = array_unique($ids);
    if(count($ids) < 1)
      continue;
    // Generate configs from the list
    if(generate_config_by_id($platform, $type, $ids, $device_conf) === FALSE)
      return false;
  }

  // Success
  return true;
}

function generate_full_config($platform, $type)
{
  global $config;

  // Nothing to do without params
  if(empty($platform) || empty($type))
    return false;

  // Format path to generator code for type-specific config elements
  $include_generator = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  // This code is mandatory
  if(!is_file($include_generator))
    return false;

  // Format path to generator code for common config elements
  $include_common = $config['includes_dir'].'/platform/'.$platform.'/common.inc.php';
  // This code is optional
  if(is_file($include_common))
    // If file exists, include it
    include_once $include_common;

  // Include generator code for type-specific elements
  include_once $include_generator;

  // This array will contain
  // generated configuration
  $device_conf = array();
  // This array will contain
  // configuration to include
  $include = array();

  // Code to execute before generator,
  // possibly to prepare common config
  // header
  $common_begin = $platform.'_begin';
  if(is_callable($common_begin))
    $common_begin($device_conf);

  // Code to execute before generator,
  // possibly to prepare type-specific
  // config header
  $section_begin = $type.'_begin';
  if(is_callable($section_begin))
    $section_begin($device_conf);

  // Process all template files
  // with generate() function
  foreach(load_templates($config['templates_dir'].'/'.$type) as $filename => $template) {
    // Generate configuration from the template
    $generate = $type.'_generate';
    // Invoke type-specific generator
    if($generate($template, $device_conf, $include) === FALSE) {
      // Generators return explicit FALSE on error
      return false;
    }
  }

  // Additional config requested by processed templates,
  // if generator used for processing supports it.
  //
  // WARNING! This can lead to inclusion loops if generators
  // allow mutual inclusion of config types. This should NEVER
  // happen. Inclusion should always be allowed in one-way only.
  // More complex structures include less complex ones, NEVER
  // the other way around. Developers, you have been warned!
  if(generate_included_config($platform, $device_conf, $include) === FALSE)
    return false;

  // Code to execute after generator,
  // possibly to create type-specific
  // config footer
  $section_end = $type.'_end';
  if(is_callable($section_end))
    $section_end($device_conf);

  // Code to execute after generator,
  // possibly to create common config
  // footer
  $common_end = $platform.'_end';
  if(is_callable($common_end))
    $common_end($device_conf);

  // Return generated configuration
  // in the platform-specific format
  return format_generated_config($platform, $device_conf);
}

function generate_configs($platform, $type, $list=NULL, $time=NULL)
{
  global $config;

  // Drop root privileges and change
  // to http daemon's user/group
  drop_privileges();

  // Split comma-separated list of template IDs
  $ids = empty($list) ? array():explode(',', $list);

  // Initialize GIT repository (if neccessary)
  vcs_init_repository($config['templates_dir']);

  // If time is defined...
  if(!empty($time)) {
    // ... checkout commit closest to the specified time
    if(!vcs_checkout($time))
      return false;
  }

  // Generate configuration in requested format
  $formatted_conf = empty($ids) ?
                      generate_full_config($platform, $type):
                      generate_config_by_id($platform, $type, $ids);

  // If time was defined...
  if(!empty($time))
    // .. reset repository back to master
    vcs_checkout();

  return $formatted_conf;
}

// **************************** GENERIC FUNCTIONS *****************************

function get_freeform_config($template, $platform, $action)
{
  if(empty($template) || empty($platform) || empty($action))
    return;

  $conf = array();

  // Find 'config' tags within current hierarchy
  foreach($template->getElementsByTagName('config') as $config) {
    // Do not search deep
    if($config->parentNode->nodeName != $template->nodeName)
      continue;
    // Tag must have 'platform' attribute to identify
    // platform this freeform config applies to
    $conf_platform = $config->getAttribute('platform');
    if(empty($conf_platform) || $platform != $conf_platform)
      continue;
    // Tag must have 'action' attribute to determine
    // where to put this free-form config
    $conf_action = $config->getAttribute('action');
    if(empty($conf_action) || $action != $conf_action)
      continue;
    // If platform matches, tag's value is a freeform
    // configuration text for specified platform
    $conf[] = $config->nodeValue;
  }

  // Return concatenated free-form config
  if(count($conf))
    return implode("\n", $conf);
}

?>
