<?php

/**
 * Copyright (C) 2020 AnimalSoft Kft.
 */

declare(strict_types=1);

error_reporting(E_ALL);

array_shift($argv);

if (!$argv) {
  $argv = ['php://stdin'];
}

$stats = [];

$unknown = 0;

foreach ($argv as $arg) {
  $file = file_get_contents($arg);

  if (preg_match('%^<div id="stats" class="stats"[^>]*?>$(.*?)^</div>$%msu', $file, $match)) {
    $match = preg_replace('%<(a|canvas|div|table|tr|td)[^>]+?>%', '<$1>', $match[1]);
    $match = strip_tags($match, '<td><tr>');
    $lines = explode('<tr>', $match);
    $lines = array_map('trim', $lines);
    $lines = array_filter($lines);

    unset($lines[1]);

    foreach ($lines as $line) {
      $columns = preg_split('%</td>[\s\r\n]*<td>%u', $line);

      if (!$columns) {
        continue;
      }

      if (2 === count($columns)) {
        [$label, $value] = $columns;
      }
      else {
        $label = 'Unknown ' . ++$unknown;
        $value = implode(' ', $columns);
      }

      $label = trim(strip_tags($label));
      $value = (float) trim(strip_tags($value));

      if (!isset($stats[$label])) {
        $stats[$label] = $value;
      }
      else {
        $stats[$label] = $value;
      }
    }

    unset($stats['Info'], $stats['Include success']);
  }
}

$stats2 = [];
foreach ($stats as $key => $value) {
  $key = str_replace(' ', '_', strtolower($key));

  $stats2[$key] = $value;
}

echo json_encode($stats2);
