<?php

/**
 * Copyright (C) 2020 AnimalSoft Kft.
 */

declare(strict_types=1);

error_reporting(E_ALL);

chdir('c:/Users/User/PhpstormProjects/rips-scanner');

$old = json_decode(file_get_contents('old.json'), TRUE);
$new = json_decode(file_get_contents('new.json'), TRUE);
?>
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <title>Rips stats</title>
  <style>
    html {
      font-family: sans-serif;
    }

    table, tr, td, th {
      border: 1px solid black;
      border-collapse: collapse;
    }

    td, th {
      padding: 3px 5px;
    }

    tbody th {
      font-weight: normal;
      text-align: left;
    }

    tr:hover {
      background: #eee;
    }

    td {
      text-align: right;
    }

    td.no {
      color: orange;
    }

    td.ok {
      color: #63C763;
    }

    td.nok {
      color: #c00;
    }
  </style>
</head>
<body>
<table>
  <thead>
  <tr>
    <th>Key</th>
    <th>Old</th>
    <th>New</th>
    <th>Change</th>
  </tr>
  </thead>
  <tbody>
  <?php foreach ($old as $key => $value): ?>
    <?php $change = ($old[$key] - $new[$key]) / $old[$key] * -100 ?>
    <tr>
      <th><?= $key ?></th>
      <td><?= $old[$key] ?></td>
      <td><?= $new[$key] ?></td>
      <td class="<?= $change ? ($change < 0 ? 'ok' : 'nok') : 'no' ?>"><?php
        printf('%+.02f%%', $change);
        ?></td>
    </tr>
  <?php endforeach ?>
  </tbody>
</table>
</body>
</html>
