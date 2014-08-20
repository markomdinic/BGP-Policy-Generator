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

// **************************** TEMPLATE FUNCTIONS ****************************

function load_template($filename)
{
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
  if(!is_dir($dirname))
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

function update_template($autotemplate)
{
  global $config;

  // Don't waste time if template or local ASN is missing
  if(empty($autotemplate) || empty($config['local_as']))
    return false;

  if(!preg_match('/^(?:AS)?(\d+)$/i', $config['local_as'], $m))
    return false;

  // Our own ASN
  $local_as = 'AS'.$m[1];

  // Process all policies in this autopolicy template
  foreach($autotemplate->getElementsByTagName('policy') as $policy) {

    // Peer's AS number is mandatory
    $peer_as = $policy->getAttribute('peer-as');
    if(empty($peer_as) || !preg_match('/^(?:AS)?(\d+)$/i', $peer_as, $m))
      return false;

    // Our peer's ASN
    $peer_as = 'AS'.$m[1];

    if(php_sapi_name() == "cli")
      echo("Fetching prefixes announced by ".$peer_as." to ".$local_as."\n");

    // To which protocol family should prefixes belong ?
    $family = $policy->getAttribute('family');
    switch($family) {
      case 'inet':
        // Get prefixes announced by <peer-as> to <local-as>
        $announced = get_announced_ipv4_prefixes($peer_as, $local_as);
        break;
      case 'inet6':
        // Get prefixes announced by <peer-as> to <local-as>
        $announced = get_announced_ipv6_prefixes($peer_as, $local_as);
        break;
      default:
        return false;
    }

    // No point going any further
    // if prefixes are missing
    if(empty($announced)) {
      echo("Got no prefixes from ".$peer_as."\n");
      return false;
    }

    echo($peer_as." announcing ".count(array_keys($announced))." autonomous systems\n");

    // Process all policy terms within current policy
    foreach($policy->getElementsByTagName('term') as $term) {
      // Look for prefix lists within match tag
      foreach($term->getElementsByTagName('match') as $match) {
        // Process all prefix list elements under match tag
        foreach($match->getElementsByTagName('prefix-list') as $p) {
          // Auto-update and generate prefix list template ?
          switch($p->getAttribute('update')) {
            case 'true':
            case 'yes':
            case 'on':
            case '1':
              // In this case, this tag's value is a regex
              // which expands this tag into a series of
              // prefix-list tags pointing to prefix lists
              // holding prefixes originated by ASNs that
              // match this regular expression
              $regex = $p->nodeValue;
              if(empty($regex))
                continue 2;

              $maxlen = "";

              // Maximum prefix length is optional
              $upto = $p->getAttribute('upto');
              if(is_numeric($upto)) {
                switch($family) {
                  case 'inet':
                    if($upto < 0 || $upto > 32)
                      continue 3;
                    break;
                  case 'inet6':
                    if($upto < 0 || $upto > 128)
                      continue 3;
                    break;
                  default:
                    continue 3;
                }
                // Prepare upto attribute for
                // prefix list generation
                $maxlen = " upto=\"".$upto."\"";
              }

              // Loop through all collected prefixes
              foreach($announced as $asn => $prefixes) {
                // Make sure ASN is in AS<n> format
                if(!preg_match('/^(?:AS)?(\d+)$/i', $asn, $m))
                  continue;
                $asn = $m[1];
                // Skip if current ASN doesn't match
                if(!preg_match('/'.$regex.'/', $asn))
                  continue;

                // Prefix list name is AS<n>
                $prefix_list_name = 'AS'.$asn;

                // Begin prefix list template
                $prefix_list = array("<?xml version=\"1.0\" standalone=\"yes\"?>");
                $prefix_list[] = "<prefix-lists>";
                $prefix_list[] = "    <prefix-list id=\"".$prefix_list_name."\" family=\"".$family."\" origin=\"".$asn."\">";

                // Add prefixes to the prefix list
                foreach($prefixes as $prefix)
                  $prefix_list[] = "        <item".$maxlen.">".$prefix."</item>";

                // End prefix list template
                $prefix_list[] = "    </prefix-list>";
                $prefix_list[] = "</prefix-lists>";

                // Write template to a file
                $fd = fopen($config['templates_dir'].'/prefixlist/'.$prefix_list_name, 'w+');
                if(!isset($fd))
                  continue 3;
                fwrite($fd, implode("\n", $prefix_list)."\n");
                fclose($fd);

                // Clone current prefix-list node
                $node = $p->cloneNode();
                if(!isset($node))
                  continue;

                // Replace node's value with
                // actual prefix-list name
                $node->nodeValue = $prefix_list_name;
                // Remove 'update' attribute
                $node->removeAttribute('update');
                // Remove 'upto' attribute
                $node->removeAttribute('upto');
                // Put cloned prefix-list node under
                // match tag, where it belongs ...
                $match->appendChild($node);
              }
              // Remove used auto-update node
              $match->removeChild($p);
              break;
          }
        }
        // There can be only one match element
        break;
      }
    }

  }

  return true;
}

function update_template_by_name($name)
{
  global $config;

  // Load specific autopolicy template
  $autotemplate = load_template($config['templates_dir'].'/autopolicy/'.$name);
  if(!isset($autotemplate)) {
    echo("Auto-policy template ".$name." not found\n");
    return false;
  }

  // Generate config templates from autopolicy template
  if(update_template($autotemplate) === FALSE)
    // Generators return explicit FALSE on error
    return false;
  $autotemplate->formatOutput = true;
  // Save generated template in the policy directory
  $autotemplate->save($config['templates_dir'].'/policy/'.$name);
}

function update_all_templates()
{
  global $config;

  // Load all autopolicy templates
  $autotemplates = load_templates($config['templates_dir'].'/autopolicy');
  if(empty($autotemplates)) {
    echo("No auto-policy templates defined\n");
    return false;
  }

  // Process all autopolicy template files
  foreach($autotemplates as $filename => $autotemplate) {
    // Generate config templates from autopolicy template
    if(update_template($autotemplate) === FALSE)
      // Generators return explicit FALSE on error
      return false;
    $autotemplate->formatOutput = true;
    // Save generated template in the policy directory
    $autotemplate->save($config['templates_dir'].'/policy/'.$filename);
  }
}

// ************************** PREFIX-LIST FUNCTIONS ***************************

function find_prefixlist_by_id($name)
{
  return find_template_by_attr('prefixlist', 'prefix-list', 'id', $name);
}

function find_prefixlist_by_origin($origin)
{
  return find_template_by_attr('prefixlist', 'prefix-list', 'origin', $origin);
}

// ***************************** POLICY FUNCTIONS *****************************

function find_policy_by_id($name)
{
  return find_template_by_attr('policy', 'policy', 'id', $name);
}

function find_policy_by_peer_as($peer_as)
{
  return find_template_by_attr('policy', 'policy', 'peer-as', $peer_as);
}

// *************************** GENERATOR FUNCTIONS ****************************

function print_generated_config(&$device_conf, $config_type)
{
  // Serialize configuration
  $config = implode("\n", $device_conf)."\n";
  // Get content type if generator defines it
  $func = $config_type.'_content_type';
  if(is_callable($func))
    $content_type = $func();
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
    default:
      // Default content type is text/plain
      $content_type = "text/plain";
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

function generate_config_by_name($platform, $type, $name, &$device_conf=array())
{
  global $config;

  // Find the requested template by name
  $find_by_name = 'find_'.$type.'_by_id';
  $element = $find_by_name($name);
  if(!isset($element))
    return false;

  // Format path to generator code
  $include_file = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  if(!is_file($include_file))
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

  // This is the selection of elements
  // to be used for config generation
  $elements = is_array($element) ? $element:array($element);
  // This is our type-specific generator name
  $generate = $type.'_generate';
  // Generate configuration for selected element(s)
  foreach($elements as $element) {
    // Invoke type-specific generator
    if($generate($element, $device_conf) === FALSE)
      // Generators return explicit FALSE on error,
      return false;
  }

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

function generate_full_config($platform, $type)
{
  global $config;

  // Format path to generator code
  $include_file = $config['includes_dir'].'/platform/'.$platform.'/'.$type.'.inc.php';
  if(!is_file($include_file))
    return false;

  // Include generator code
  include_once $include_file;

  // This array will contain
  // generated configuration
  $device_conf = array();

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
    if($generate($template, $device_conf) === FALSE)
      // Generators return explicit FALSE on error
      return false;
  }

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

// **************************** GENERIC FUNCTIONS *****************************

function get_freeform_config($template, $platform, $action)
{
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
