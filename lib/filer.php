<?php
/**
 *
 * RIPS - A static source code analyser for vulnerabilities in PHP scripts
 * by Johannes Dahse (johannes.dahse@rub.de)
 *
 *
 * Copyright (C) 2012 Johannes Dahse
 * Copyright (C) 2020 AnimalSoft Kft.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 **/

/**
 * Get all php files from directory, including all subdirectories
 *
 * @param string $path
 * @param bool $scan_subdirs
 *
 * @return string[]
 */
function read_recursiv(string $path, bool $scan_subdirs): array {
  global $FILETYPES, $SKIPFILES, $SKIPDIRS;

  $result = [];

  foreach (scandir($path, SCANDIR_SORT_NONE) as $file) {
    if ('.' === $file || '..' === $file) {
      continue;
    }

    $name = $path . '/' . $file;

    if (is_dir($name)) {
      if ($scan_subdirs && !in_array($file, $SKIPDIRS)) {
        $result = array_merge($result, read_recursiv($name, TRUE));
      }
    }
    elseif (0 !== strpos($file, 'x_') && in_array(pathinfo($file, PATHINFO_EXTENSION), $FILETYPES) && !in_array($file, $SKIPFILES)) {
      $result[] = $name;
    }
  }

  return $result;
}
