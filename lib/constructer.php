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

// variable declarations = childs
class VarDeclare {

  public $id;

  public $tokens;

  public $tokenscanstart;

  public $tokenscanstop;

  public $value;

  public $comment;

  public $line;

  public $marker;

  public $dependencies;

  public $stopvar;

  public $array_keys;

  public function __construct($tokens = [], $comment = '') {
    $this->id = 0;
    $this->tokens = $tokens;
    $this->tokenscanstart = 0;
    $this->tokenscanstop = count($tokens);
    $this->value = '';
    $this->comment = $comment;
    $this->line = '';
    $this->marker = 0;
    $this->dependencies = [];
    $this->stopvar = FALSE;
    $this->array_keys = [];
  }
}

// group vulnerable parts to one vulnerability trace
class VulnBlock {

  public $uid;

  public $vuln;

  public $category;

  public $treenodes;

  public $sink;

  public $dataleakvar;

  public $alternates;

  public function __construct($uid = '', $category = 'match', $sink = '') {
    $this->uid = $uid;
    $this->vuln = FALSE;
    $this->category = $category;
    $this->treenodes = [];
    $this->sink = $sink;
    $this->dataleakvar = [];
    $this->alternates = [];
  }
}

// used to store new finds
class VulnTreeNode {

  public $id;

  public $value;

  public $dependencies;

  public $title;

  public $name;

  public $marker;

  public $lines;

  public $filename;

  public $children;

  public $funcdepend;

  public $funcparamdepend;

  public $foundcallee;

  public $get;

  public $post;

  public $cookie;

  public $files;

  public $server;

  public function __construct($value = NULL) {
    $this->id = 0;
    $this->value = $value;
    $this->title = '';
    $this->dependencies = [];
    $this->name = '';
    $this->marker = 0;
    $this->lines = [];
    $this->filename = '';
    $this->children = [];
    $this->funcdepend = '';
    $this->funcparamdepend = NULL;
    $this->foundcallee = FALSE;
  }
}

// information gathering finds
class InfoTreeNode {

  public $value;

  public $dependencies;

  public $name;

  public $lines;

  public $title;

  public $filename;

  public function __construct($value = NULL) {
    $this->title = 'File Inclusion';
    $this->value = $value;
    $this->dependencies = [];
    $this->name = '';
    $this->lines = [];
    $this->filename = '';
  }
}

// function declaration
class FunctionDeclare {

  public $value;

  public $tokens;

  public $name;

  public $line;

  public $marker;

  public $parameters;

  public function __construct($tokens) {
    $this->value = '';
    $this->tokens = $tokens;
    $this->name = '';
    $this->line = 0;
    $this->marker = 0;
    $this->parameters = [];
  }
}
