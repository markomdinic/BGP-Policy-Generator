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

function junosxsl_envelope($stage, &$conf)
{
  global $config;

  $script = file_get_contents($config['includes_dir'].'/platform/junosxsl/'.$stage.'.xsl');
  if(empty($script))
    return false;

  foreach(explode("\n", $script) as $line)
    $conf[] = $line;

  return true;
}

?>
