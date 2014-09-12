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

    // To which protocol family should prefixes belong ?
    $family = $policy->getAttribute('family');
    switch($family) {
      case 'inet':
        status_message("Fetching af inet prefixes announced by AS".$peer_as." to AS".$local_as." ...\n", $statusmsg);
        // Get prefixes announced by <peer-as> to <local-as>
        $announced = get_announced_ipv4_prefixes('AS'.$peer_as, 'AS'.$local_as);
        break;
      case 'inet6':
        status_message("Fetching af inet6 prefixes announced by AS".$peer_as." to AS".$local_as." ...\n", $statusmsg);
        // Get prefixes announced by <peer-as> to <local-as>
        $announced = get_announced_ipv6_prefixes('AS'.$peer_as, 'AS'.$local_as);
        break;
      default:
        // Next policy
        continue 2;
    }

    // No point going any further
    // if prefixes are missing
    if(empty($announced)) {
      status_message("Got no af ".$family." prefixes from AS".$peer_as.".\n", $statusmsg);
      return;
    }

    status_message("AS".$peer_as." is announcing (af ".$family.") ".count(array_keys($announced))." autonomous systems.\n", $statusmsg);

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

      // This variable will hold the number
      // of <auto-prefix-list> tags specified
      // within this term's <match> element
      $auto_prefix_list_count = 0;

      // This array will receive match and set
      // elements built as strings in XML format
      $term_elements = array();

      // Process match element inside current term
      foreach($term->getElementsByTagName('match') as $match) {

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

          // Get the include flag, if defined
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
            case 'yes':
            case 'on':
            case '1':
              $aggregate = true;
              break;
            default:
              $aggregate = false;
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
          ksort($announced);

          // Loop through all collected prefixes
          foreach($announced as $origin_as => $prefixes) {

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
            if($aggregate) {
              switch($family) {
                case 'inet':
                  // ... aggregate IPv4 prefixes
                  $prefixes = aggregate_ipv4($prefixes);
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
            sort($prefixes);

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
              status_message("Aborting: failed to write prefix list file ".$prefix_list_name.".\n", $statusmsg);
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

        // Copy the rest of match conditions unless
        // <match> contains <auto-prefix-list> tags
        // that produced no prefix lists, thus making
        // the <match> section invalid
        if($auto_prefix_list_count < 1 || count($match_elements) > 0) {
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

      // Copy all set statements unless <match> contains
      // <auto-prefix-list> tags that produced no prefix
      // lists, thus making the <match> section invalid
      // and, in turn, the entire <term>, which makes
      // the <set> section unneccessary
      if($auto_prefix_list_count < 1 || count($term_elements) > 0) {
        // Process set element inside current term
        foreach($term->getElementsByTagName('set') as $set) {
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
          // There can be only one set element
          break;
        }
      }

      // If term is not empty ...
      if(count($term_elements) > 0) {
        // ... add it to the policy
        $policy_elements[] = "<term id=\"".$term_id."\" action=\"".$term_action."\">";
        $policy_elements[] = implode("\n", $term_elements);
        $policy_elements[] = "</term>";
      // Otherwise, if term doesn't contain
      // failed <auto-prefix-list> tags ...
      } elseif($auto_prefix_list_count < 1)
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
    status_message("Updating autopolicy template ".$id." ...\n", $log);

    // Load specific autopolicy template
    $autotemplate = load_template($config['templates_dir'].'/autopolicy/'.$id);
    if(!isset($autotemplate)) {
      status_message("Autopolicy template ".$id." not found.\n", $log);
      continue;
    }

    // Generate config templates from autopolicy template
    $template = update_template($autotemplate, $log);
    if(!isset($template)) {
      status_message("Autopolicy ".$id." update failed.\n", $log);
      continue;
    }
    // Make XML output properly formatted
    $template->formatOutput = true;
    // Save updated template to the policy directory
    $template->save($config['templates_dir'].'/policy/'.$id);

    status_message("Autopolicy ".$id." successfully updated.\n", $log);
  }

  status_message("Done.\n", $log);

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

  status_message("Updating all autopolicy templates ...\n", $log);

  // Process all autopolicy template files
  foreach($autotemplates as $filename => $autotemplate) {
    // Update template from autopolicy template
    $template = update_template($autotemplate, $log);
    // If template update failed ...
    if(!isset($template))
      // ... move on to the next template
      continue;
    // Make XML output properly formatted
    $template->formatOutput = true;
    // Save updated template to the policy directory
    $template->save($config['templates_dir'].'/policy/'.$filename);
  }

  status_message("Done.\n", $log);

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

  // Update autopolicies
  $res = empty($ids) ?
            update_all_templates($log):
            update_template_by_id($ids, $log);

  // If update was successful ..
  if($res)
    // ... commit changes in the repository
    vcs_commit($config['templates_dir'], $log);
  // Otherwise ...
  else
    // ... reset to last good commit
    vcs_reset();

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

function print_generated_config(&$device_conf, $config_type)
{
  // Nothing to do ?
  if(empty($device_conf) || empty($config_type))
    return;

  // Serialize configuration
  $config = "";
  // We could use the implode() here, but that might
  // hit the PHP allowed memory limit, so we rather
  // concatenate config lines by hand
  foreach($device_conf as $line)
    $config .= $line."\n";
  // Get content type if generator defines it
  $func = $config_type.'_content_type';
  if(is_callable($func))
    $content_type = $func();
  // Default content type is text/plain
  if(empty($content_type))
    $content_type = "text/plain";
  // Detect content type and reformat, if possible
  switch($content_type) {
    case 'text/xml':
    case 'text/xsl':
    case 'text/xslt':
      $doc = new DomDocument;
      $doc->preserveWhiteSpace = false;
      $doc->validateOnParse = true;
      // Load XML as is
      $doc->loadXML($config);
      // Make it pretty
      $doc->formatOutput = true;
      // Put it back nicely formatted
      $config = $doc->saveXML();
      break;
  }
  // Generate HTTP headers if not called from CLI
  if(!(php_sapi_name() == 'cli')) {
    header('Content-Type: '.$content_type);
    header('Content-Length: '.strlen($config));
  }
  // Dump generated configuration
  echo($config);
}

function generate_config_by_id($platform, $type, $ids, &$device_conf=array())
{
  global $config;

  // Need these parameters
  if(empty($platform) || empty($type) ||
     empty($ids) || !isset($device_conf))
    return false;

  // Format path to generator code
  $include_file = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  if(!is_file($include_file))
    return false;

  // Find the requested template by id
  $find_by_id = 'find_'.$type.'_by_id';
  $element = $find_by_id($ids);
  if(!isset($element))
    return false;

  // Include generator code
  include_once $include_file;

  // Device-specific begin/end generators
  // should be called if we are starting
  // with an empty configuration
  $fresh = empty($device_conf) ? true:false;

  // Code to execute before generator,
  // possibly to prepare config header,
  // but only if we are starting fresh
  if($fresh) {
    $begin = $type.'_begin';
    if(is_callable($begin))
      $begin($device_conf);
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
    $end = $type.'_end';
    if(is_callable($end))
      $end($device_conf);
  }

  // If external config storage wasn't given ...
  if(func_num_args() < 4)
    // ... dump generated configuration
    print_generated_config($device_conf, $type);

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

  // Format path to generator code
  $include_file = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  if(!is_file($include_file))
    return false;

  // Include generator code
  include_once $include_file;

  // This array will contain
  // generated configuration
  $device_conf = array();
  // This array will contain
  // configuration to include
  $include = array();

  // Code to execute before generator,
  // possibly to prepare config header
  $begin = $type.'_begin';
  if(is_callable($begin))
    $begin($device_conf);

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
  // possibly to create config footer
  $end = $type.'_end';
  if(is_callable($end))
    $end($device_conf);

  // Dump generated configuration
  print_generated_config($device_conf, $type);

  // Success
  return true;
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
  $res = empty($ids) ?
            generate_full_config($platform, $type):
            generate_config_by_id($platform, $type, $ids);

  // If time was defined...
  if(!empty($time))
    // .. reset repository back to master
    vcs_checkout();

  return $res;
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
