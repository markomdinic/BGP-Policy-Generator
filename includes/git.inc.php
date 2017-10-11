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

function git()
{
  global $config;

  // Don't waste my time
  if(func_num_args() < 1 ||
     !isset($config['git']) ||
     !is_executable($config['git']))
    return false;

  $args = func_get_args();
  if(!is_array($args))
    return false;

  // Run git command
  exec($config['git']." ".implode(' ', $args)." 2>/dev/null", $output, $retval);
  if($retval != 0)
    return false;

  return $output;
}

function git_init($path)
{
  if(empty($path) || !is_dir($path))
    return false;

  return git('init', $path) !== FALSE ? true:false;
}

function git_status()
{
  return git('status') !== FALSE ? true:false;
}

function git_checkout($commit)
{
  if(empty($commit))
    return false;

  return git('checkout', $commit) !== FALSE ? true:false;
}

function git_add($path)
{
  if(empty($path) || (!is_dir($path) && !is_file($path)))
    return false;

  return git('add', '-A', $path) !== FALSE ? true:false;
}

function git_reset($path=NULL)
{
  if(!empty($path) && (is_dir($path) || is_file($path)))
    return git('reset', $path);

  return git('reset') !== FALSE ? true:false;
}

function git_commit($comment, $name=NULL, $email=NULL)
{
  if(empty($comment))
    return false;

  $args = "-m \"".$comment."\"";
  if(!empty($name) && !empty($email))
    $args .= " --author=\"".$name." <".$email.">\"";

  return git('commit', $args) !== FALSE ? true:false;
}

function git_log($params=NULL)
{
  return git('log', $params);
}

function git_diff($commit)
{
  if(empty($commit))
    return false;

  return git('diff', $commit);
}

function git_list_before($time)
{
  if(empty($time))
    return false;

  return git('rev-list', '--before', $time, 'master');
}

function git_list_after($time)
{
  if(empty($time))
    return false;

  return git('rev-list', '--after', $time, 'master');
}

?>
