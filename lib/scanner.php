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

class Scanner {

  public $file_name;

  public $scan_functions;

  public $info_functions;

  public $source_functions;

  public $var_declares_global;

  public $globals_from_function;

  public $in_class;

  public $class_name;

  public $vuln_classes;

  public $class_vars;

  public $brace_save_class;

  public $in_function;

  public $function_obj;

  public $var_declares_local;

  public $put_in_global_scope;

  public $brace_save_func;

  public $braces_open;

  public $ignore_requirement;

  public $dependencies;

  public $dependencytokens;

  public $securedby;

  public $ignore_securing_function;

  public $userfunction_secures;

  public $userfunction_taints;

  public $comment;

  public $inc_file_stack;

  public $inc_map;

  public $include_paths;

  public $file_pointer;

  public $lines_stack;

  public $lines_pointer;

  public $tif;

  public $tif_Stack;

  public $tokens;

  public $last_dependency;

  public function __construct($file_name, $scan_functions, $info_functions, $source_functions) {
    $this->file_name = $file_name;
    $this->scan_functions = $scan_functions;
    $this->info_functions = $info_functions;
    $this->source_functions = $source_functions;

    $this->var_declares_global = [];
    $this->var_declares_local = [];
    $this->put_in_global_scope = [];
    $this->globals_from_function = [];

    $this->in_class = FALSE;
    $this->class_name = '';
    $this->vuln_classes = [];
    $this->class_vars = [];

    $this->in_function = 0;
    $this->function_obj = NULL;

    $this->in_condition = 0;
    $this->braces_open = 0;
    $this->brace_save_func = -1;
    $this->brace_save_class = -1;
    $this->ignore_requirement = FALSE;
    $this->dependencies = [];
    $this->dependencytokens = [];

    $this->securedby = [];
    $this->ignore_securing_function = FALSE;
    $this->userfunction_secures = FALSE;
    $this->userfunction_taints = FALSE;
    $this->comment = '';

    $this->inc_file_stack = [realpath($this->file_name)];
    $this->inc_map = [];
    $this->include_paths = Analyzer::get_ini_paths(ini_get('include_path'));
    $this->file_pointer = end($this->inc_file_stack);
    if (!isset($GLOBALS['file_sinks_count'][$this->file_pointer])) {
      $GLOBALS['file_sinks_count'][$this->file_pointer] = 0;
    }
    $this->lines_stack = [];
    $this->lines_stack[] = $this->file($this->file_name);
    $this->lines_pointer = end($this->lines_stack);
    $this->tif = 0; // tokennr in file
    $this->tif_stack = [];

    // preload output
    echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . ' (tokenizing)|' . $GLOBALS['timeleft'] . '|' . "\n";

    if (empty($_POST['statnow'])) {
      @ob_flush();
      flush();
    }

    // tokenizing
    $tokenizer = new Tokenizer($this->file_pointer);
    $this->tokens = $tokenizer->tokenize(implode('', $this->lines_pointer));
    unset($tokenizer);

    // add auto includes from php.ini
    /*
    if (ini_get('auto_prepend_file')) {
      $this->add_auto_include(ini_get('auto_prepend_file'), TRUE);
    }
    if (ini_get('auto_append_file')) {
      $this->add_auto_include(ini_get('auto_append_file'), FALSE);
    }
    */
  }

  // create require tokens for auto_prepend/append_files and add to tokenlist
  public function add_auto_include($paths, $beginning) {
    $paths = Analyzer::get_ini_paths($paths);
    $addtokens = [];
    foreach ($paths as $file) {
      $includetokens = [
        [T_REQUIRE, 'require', 0],
        [T_CONSTANT_ENCAPSED_STRING, "'$file'", 0],
        ';',
      ];
      $addtokens = array_merge($addtokens, $includetokens);
    }
    if ($beginning) {
      $this->tokens = array_merge($addtokens, $this->tokens);
    }
    else {
      $this->tokens = array_merge($this->tokens, $addtokens);
    }
  }

  // traces recursivly parameters and adds them as child to parent
  // returns true if a parameter is tainted by userinput (1=directly tainted, 2=function param)
  public function scan_parameter($mainparent, $parent, $var_token, $var_keys = [], $last_token_id, $var_declares, $var_declares_global = [], $userinput, $F_SECURES = [], $return_scan = FALSE, $ignore_securing = FALSE, $secured = FALSE) {
    #print_r(func_get_args());echo "\n----------------\n";
    $vardependent = FALSE;

    $var_name = $var_token[1];
    // constants
    if ('$' !== $var_name[0]) {
      $var_name = strtoupper($var_name);
    }
    // variables
    else {
      // reconstruct array key values $a[$b]
      if (isset($var_token[3])) {
        for ($k = 0, $kMax = count($var_token[3]); $k < $kMax; $k++) {
          if (is_array($var_token[3][$k])) {
            $var_token[3][$k] = Analyzer::get_tokens_value(
              $this->file_pointer,
              $var_token[3][$k],
              $var_declares,
              $var_declares_global,
              $last_token_id
            );
          }
        }
      }

      // handle $GLOBALS and $_SESSIONS
      if (isset($var_token[3])) {
        if ('$GLOBALS' == $var_name && !isset($var_declares[$var_name]) && !empty($var_token[3][0])) {
          $var_name = '$' . str_replace(["'", '"'], '', $var_token[3][0]);
          // php $GLOBALS: ignore previous local vars and take only global vars
          $var_declares = $var_declares_global;
        }
        elseif ('$_SESSION' === $var_name && !isset($var_declares[$var_name]) && !empty($var_declares_global)) {
          // $_SESSION data is handled as global variables
          $var_declares = array_merge($var_declares_global, $var_declares);
        }
      }

      // if a register_globals implementation is present shift it to the beginning of the var_declare array
      if (isset($var_declares['register_globals']) && !in_array($var_name, Sources::$V_USERINPUT)
        && (!$this->in_function || in_array($var_name, $this->put_in_global_scope))) {
        if (!isset($var_declares[$var_name])) {
          $var_declares[$var_name] = $var_declares['register_globals'];
        }
        else {
          foreach ($var_declares['register_globals'] as $glob_obj) {
            if ($glob_obj->id < $last_token_id) {
              $var_declares[$var_name][] = $glob_obj;
            }
          }
        }
      }
    }

    // check if var declaration could be found for this var
    // and if the latest var_declares id is smaller than the last_token_id, otherwise continue with function parameters
    #echo "trying: $var_name, isset: ".(int)(isset($var_declares[$var_name])).", ".end($var_declares[$var_name])->id." < ".$last_token_id."?\n";
    if (isset($var_declares[$var_name]) && (end($var_declares[$var_name])->id < $last_token_id || $userinput)) {
      foreach ($var_declares[$var_name] as $var_declare) {
        // check if array keys are the same (if it is an array)
        $array_key_diff = [];
        if (!empty($var_token[3]) && !empty($var_declare->array_keys)) {
          $array_key_diff = array_diff_assoc($var_token[3], $var_declare->array_keys);
        }

        #print_r($var_declares[$var_name]);
        #echo "<br>var:".$var_name; echo " varkeys:";print_r($var_token[3]); echo " declarekeys:";print_r($var_declare->array_keys); echo " diff:"; print_r($array_key_diff); echo " |||";

        #if(!empty($var_declare->array_keys)) die(print_r($var_declare->array_keys) . print_r($var_keys));

        if ($var_declare->id < $last_token_id && (empty($array_key_diff) || in_array('*', $array_key_diff) || in_array('*', $var_declare->array_keys)) /* && (empty($var_declare->array_keys) || empty($var_keys) || $var_declare->array_keys == $var_keys || in_array('*', $var_keys) || in_array('*', $array_key_diff) || in_array('*', $var_declare->array_keys) ) */) {
          $comment = '';
          // add line to output
          if (count($mainparent->lines) < MAXTRACE) {
            $clean_vars_before_ifelse = FALSE;
            // add same var_name with different dependencies
            if (!empty($var_declare->dependencies) && $mainparent->dependencies != $var_declare->dependencies) {
              foreach ($var_declare->dependencies as $deplinenr => $dependency) {
                if (!isset($mainparent->dependencies[$deplinenr]) && $deplinenr != $var_declare->line) {
                  $vardependent = TRUE;
                  $comment .= tokenstostring($dependency) . ', ';
                  // if dependencie has an ELSE clause, same vars before are definetely overwritten
                  if (T_ELSE === $dependency[count($dependency) - 1][0]) {
                    $clean_vars_before_ifelse = TRUE;
                  }
                }
              }
            }

            // stop at var declarations before if else statement. they are overwritten
            if ($clean_vars_before_ifelse) {
              for ($c = 0, $cMax = count($var_declares[$var_name]); $c < $cMax; $c++) {
                if (count($var_declares[$var_name][$c]->dependencies) < count($var_declare->dependencies)) {
                  $var_declares[$var_name][$c - 1]->stopvar = TRUE;
                  break;
                }
              }
            }

            $mainparent->lines[] = $var_declare->line;
            $var_trace = new VarDeclare('');
            $parent->children[] = $var_trace;
          }
          else {
            $stop = new VarDeclare('... Trace stopped.');
            $parent->children[] = $stop;
            return $userinput;
          }

          // find other variables in this line
          $tokens = $var_declare->tokens;
          $last_scanned = '';
          $last_userinput = FALSE;
          $in_arithmetic = FALSE;
          $in_securing = FALSE;
          $parentheses_open = 0;
          $parentheses_save = -1;

          $tainted_vars = [];
          $var_count = 1;

          for ($i = $var_declare->tokenscanstart; $i < $var_declare->tokenscanstop; $i++) {
            $this_one_is_secure = FALSE;
            if (is_array($tokens[$i])) {
              // if token is variable or constant
              if ((T_VARIABLE === $tokens[$i][0] && T_OBJECT_OPERATOR !== $tokens[$i + 1][0])
                || (T_STRING === $tokens[$i][0] && '(' !== $tokens[$i + 1])) {
                $var_count++;

                // check if typecasted
                if ((is_array($tokens[$i - 1])
                    && in_array($tokens[$i - 1][0], Tokens::T_CASTS))
                  || (is_array($tokens[$i + 1])
                    && in_array($tokens[$i + 1][0], Tokens::T_ARITHMETIC))) {
                  // mark user function as a securing user function
                  $GLOBALS['userfunction_secures'] = TRUE;
                  $this_one_is_secure = TRUE;

                  $var_trace->marker = 2;
                }

                // check for automatic typecasts by arithmetic
                if (in_array($tokens[$i - 1], Tokens::S_ARITHMETIC)
                  || in_array($tokens[$i + 1], Tokens::S_ARITHMETIC)) {
                  // mark user function as a securing user function
                  $GLOBALS['userfunction_secures'] = TRUE;

                  $in_arithmetic = TRUE;

                  $var_trace->marker = 2;
                }

                // scan in global scope
                $userinput = $this->scan_parameter(
                  $mainparent,
                  $var_trace,
                  $tokens[$i],
                  $var_keys,
                  $var_declare->id,
                  ((is_array($tokens[$i - 1]) && T_GLOBAL === $tokens[$i - 1][0]) || '$' !== $tokens[$i][1][0]) ? $var_declares_global : $var_declares,  // global or local scope
                  $var_declares_global,
                  $userinput,
                  $F_SECURES,
                  $return_scan,
                  $ignore_securing,
                  ($this_one_is_secure || $in_securing || $in_arithmetic)
                );

                // consider securing applied to parent variable
                if ($secured && $GLOBALS['verbosity'] < 3 && !$last_userinput) {
                  $userinput = FALSE;
                }

                // add tainted variable to the list to get them highlighted in output
                if ($userinput && !$last_userinput) {
                  $tainted_vars[] = $var_count;
                }
              }
              // if in foreach($bla as $key=>$value) dont trace $key, $value back
              else {
                if (T_AS === $tokens[$i][0]) {
                  break;
                }
                // also check for userinput from functions returning userinput

                if (in_array($tokens[$i][1], $this->source_functions)) {
                  $userinput = TRUE;
                  $var_trace->marker = 4;
                  $mainparent->title = 'Userinput returned by function <i>' . $tokens[$i][1] . '()</i> reaches sensitive sink.';

                  if ($return_scan) {
                    $GLOBALS['userfunction_taints'] = TRUE;
                  }
                  // userinput received in function, just needs a trigger
                  elseif ($this->in_function) {
                    $this->addtriggerfunction($mainparent);
                  }

                  // we could return here to not scan all parameters of the tainting function
                  // however we would need to add the line manually to the output here
                }
                // detect securing functions
                elseif (!$ignore_securing && ((is_array($F_SECURES) && in_array($tokens[$i][1], $F_SECURES))
                    || (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_SECURING_STRING']))
                    || (in_array($tokens[$i][0], Tokens::T_CASTS) && '(' === $tokens[$i + 1]))) {
                  $parentheses_save = $parentheses_open;
                  $in_securing = TRUE;
                  $this->securedby[] = $tokens[$i][1];
                }
                //detect insecuring functions (functions that make previous securing useless)
                elseif (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_INSECURING_STRING'])) {
                  $parentheses_save = $parentheses_open;
                  $ignore_securing = TRUE;
                }
                // if this is a vuln line, it has already been scanned -> return
                else {
                  if (((in_array($tokens[$i][0], Tokens::T_FUNCTIONS)
                        && isset($GLOBALS['scan_functions'][$tokens[$i][1]]))
                      || isset(Info::$F_INTEREST[$tokens[$i][1]]))
                    // ignore oftenly used preg_replace() and alike
                    && !isset($GLOBALS['F_CODE'][$tokens[$i][1]])
                    && !isset($GLOBALS['F_REFLECTION'][$tokens[$i][1]])
                    && !isset($GLOBALS['F_OTHER'][$tokens[$i][1]])) {
                    $var_trace->value = highlightline($tokens, $comment . $var_declare->comment . ', trace stopped', $var_declare->line);
                    $var_trace->line = $var_declare->line;
                    return $userinput;
                  }
                  // check for automatic typecasts by arithmetic assignment

                  if (in_array($tokens[$i][0], Tokens::T_ASSIGNMENT_SECURE)) {
                    // mark user function as a securing user function
                    $GLOBALS['userfunction_secures'] = TRUE;
                    $secured = 'arithmetic assignment';

                    $userinput = FALSE;  // first variable before operator has alread been traced, ignore
                    $var_trace->marker = 2;
                  }
                  // func_get_args()
                  elseif ('func_get_args' === $tokens[$i][1] && $this->in_function && T_STRING === $tokens[$i][0]) {
                    $this->addfunctiondependend($mainparent, $parent, $return_scan, -1);
                    $userinput = 2;
                  }
                  // func_get_arg()
                  elseif ('func_get_arg' === $tokens[$i][1] && $this->in_function && T_STRING === $tokens[$i][0]) {
                    $this->addfunctiondependend($mainparent, $parent, $return_scan, $tokens[$i + 2][1]);
                    $userinput = 2;
                  }
                }
              }
            }
            // string concat disables arithmetic
            elseif ('.' === $tokens[$i]) {
              $in_arithmetic = FALSE;
            }
            // watch opening parentheses
            elseif ('(' === $tokens[$i]) {
              $parentheses_open++;
            }
            // watch closing parentheses
            elseif (')' === $tokens[$i]) {
              $parentheses_open--;
              if ($parentheses_open === $parentheses_save) {
                $parentheses_save = -1;
                $in_securing = FALSE;
                $ignore_securing = FALSE;
              }
            }

            // save userinput (true|false) for vars in same line
            $last_userinput = $userinput;
          }

          // add highlighted line to output, mark tainted vars
          $var_trace->value = highlightline($tokens, $var_declare->comment . $comment, $var_declare->line, FALSE, FALSE, $tainted_vars);
          $var_trace->line = $var_declare->line;

          // we only need the last var declaration, other declarations have been overwritten
          // exception: if elseif statements:
          // if else at least overwrites vars before if else statement (else always triggers)
          if (($userinput || !$vardependent || $var_declare->stopvar) && !in_array('*', $array_key_diff)) {
            break;
          }
        }
      }
    }
    // if var comes from function parameter AND has not been overwritten with static content before (else)
    elseif ($this->in_function && in_array($var_name, $this->function_obj->parameters) && ($GLOBALS['verbosity'] >= 3 || empty($secured))) {
      $key = array_search($var_name, $this->function_obj->parameters);
      $this->addfunctiondependend($mainparent, $parent, $return_scan, $key);
      $userinput = 2;
    }
    // register globals
    elseif (SCAN_REGISTER_GLOBALS && T_VARIABLE === $var_token[0] && empty($secured) && !in_array($var_name, Sources::$V_USERINPUT) && (!$this->in_function || (in_array($var_name, $this->put_in_global_scope) && !in_array($var_name, $this->function_obj->parameters))) && !in_array($var_name, $GLOBALS['SKIPVARS'])) {
      // add highlighted line to output, mark tainted vars
      $var_trace = new VarDeclare('');
      $parent->children[] = $var_trace;
      $var_trace->value = highlightline([
        [T_VARIABLE, $var_name, 0],
        [
          T_CONSTANT_ENCAPSED_STRING,
          ' is not initialized and ' . PHPDOC . 'register_globals is enabled',
          0,
        ],
      ], $var_declare->comment . $comment, 0, FALSE, FALSE, $tainted_vars);
      $var_trace->line = 0;
      $var_trace->marker = 1;
      $userinput = TRUE;
      $this->addexploitparameter($mainparent, '$_GET', str_replace('$', '', $var_name));
    }


    // if var is userinput, return true directly
    if (in_array($var_name, Sources::$V_USERINPUT) && empty($secured)) {
      // check if userinput variable has been overwritten
      $overwritten = FALSE;
      if (isset($var_declares[$var_name])) {
        foreach ($var_declares[$var_name] as $var) {
          // check if array keys are the same (if it is an array)
          $array_key_diff = FALSE;
          if (isset($var_token[3]) && !empty($var_declare->array_keys)) {
            $array_key_diff = array_diff_assoc($var_token[3], $var_declare->array_keys);
          }

          // if there is a var declare for this userinput !except the same line!: overwritten
          if ($last_token_id != $var->id && !$array_key_diff) {
            $overwritten = TRUE;
          }
        }
      }

      if (!$overwritten) {
        // add userinput markers to mainparent object
        if (isset($var_token[3])) {
          $parameter_name = str_replace(["'", '"'], '', $var_token[3][0]);
        }
        else {
          $parameter_name = 'x';
        }

        // mark tainted, but only specific $_SERVER parameters
        if ('$_SERVER' !== $var_name
          || in_array($parameter_name, Sources::$V_SERVER_PARAMS)
          || 'HTTP_' === substr($parameter_name, 0, 5)) {
          $userinput = TRUE;
          $parent->marker = 1;

          $this->addexploitparameter($mainparent, $var_name, $parameter_name);

          // analyse depencies for userinput and add it for exploit creator
          if (!empty($mainparent->dependencies)) {
            foreach ($mainparent->dependencies as $dtokens) {
              for ($t = 0, $tMax = count($dtokens); $t < $tMax; $t++) {
                if (T_VARIABLE === $dtokens[$t][0] && in_array($dtokens[$t][1], Sources::$V_USERINPUT) && ('$_SERVER' !== $dtokens[$t][1] || in_array($dtokens[$t][3][0], Sources::$V_SERVER_PARAMS)
                    || 'HTTP_' === substr($dtokens[$t][3][0], 0, 5))) {
                  $this->addexploitparameter($mainparent, $dtokens[$t][1], str_replace([
                    '"',
                    "'",
                  ], '', $dtokens[$t][3][0]));
                }
              }
            }
          }
        }

        // userinput received in function, just needs a trigger
        if ($this->in_function && !$return_scan) {
          $this->addtriggerfunction($mainparent);
        }
      }
    }

    return $userinput;
  }

  // add exploit parameter to parent
  public function addexploitparameter($parent, $type, $parameter_name) {
    if (!empty($parameter_name)) {
      switch ($type) {
        case '$_GET':
          $parent->get[] = $parameter_name;
          break;
        case '$HTTP_GET_VARS':
          $parent->get[] = $parameter_name;
          break;
        case '$_REQUEST':
          $parent->get[] = $parameter_name;
          break;
        case '$HTTP_REQUEST_VARS':
          $parent->get[] = $parameter_name;
          break;
        case '$_POST':
          $parent->post[] = $parameter_name;
          break;
        case '$HTTP_POST_VARS':
          $parent->post[] = $parameter_name;
          break;
        case '$HTTP_RAW_POST_DATA':
          $parent->post[] = $parameter_name;
          break;
        case '$_COOKIE':
          $parent->cookie[] = $parameter_name;
          break;
        case '$HTTP_COOKIE_VARS':
          $parent->cookie[] = $parameter_name;
          break;
        case '$_FILES':
          $parent->files[] = $parameter_name;
          break;
        case '$HTTP_POST_FILES':
          $parent->files[] = $parameter_name;
          break;
        case '$_SERVER':
          $parent->server[] = $parameter_name;
          break;
      }
    }
  }

  // add function to output that triggers something by call
  public function addtriggerfunction($mainparent) {
    // add dependency and mark this as interesting function
    $mainparent->dependencies[$this->function_obj->lines[0]] = $this->function_obj->tokens;
    $mainparent->title = "Userinput reaches sensitive sink when function <i>{$this->function_obj->name}()</i> is called.";

    // add function to scanlist
    $mainparent->funcdepend = $this->function_obj->name;
    // with all parameters as valuable since userinput comes from inside the func
    $GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][0][0] = 0;
    // no securings
    $GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][1] = [];
    // doesnt matter if called with userinput or not
    $GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][3] = TRUE;
  }

  // add function declaration to parent and mark the block as dependend of this function calls
  public function addfunctiondependend($mainparent, $parent, $return_scan, $key) {
    // add child with function declaration
    $func_name = $this->function_obj->name;
    $mainparent->lines[] = $this->function_obj->lines[0];
    if (3 !== $this->function_obj->marker) {
      $this->function_obj->value = highlightline($this->function_obj->tokens, '', $this->function_obj->lines[0]);
      // mark as potential userinput
      $this->function_obj->marker = 3;
    }
    $parent->children[] = $this->function_obj;

    // add function to scanlist
    if (!$return_scan) {
      $mainparent->funcdepend = $func_name;
      // $mainparent->funcdependparam != $GLOBALS['user_functions'][$this->file_name][$func_name][0]
      $mainparent->funcparamdepend[] = $key + 1;

      // with potential parameters
      $map = $key < 0 ? 0 : $key;
      // scan this userfunction with the vuln parameter
      $GLOBALS['user_functions'][$this->file_name][$func_name][0][$map] = $key + 1;
      // and with according securing functions from original find
      $GLOBALS['user_functions'][$this->file_name][$func_name][1] = $GLOBALS['scan_functions'][$mainparent->name][1] ?? $GLOBALS['user_functions'][$this->file_name][$mainparent->name][1];
    }
  }

  // add a variable to the varlist
  public function variable_add($var_name, $tokens, $comment = '', $tokenscanstart, $tokenscanstop, $linenr, $id, $array_keys = [], $additional_keys = []) {
    // add variable declaration to beginning of varlist
    $new_var = new VarDeclare($tokens, $this->comment . $comment);
    $new_var->line = $linenr;
    $new_var->id = $id;

    if ($tokenscanstart) {
      $new_var->tokenscanstart = $tokenscanstart;
    }
    if ($tokenscanstop) {
      $new_var->tokenscanstop = $tokenscanstop;
    }

    // add dependencies
    foreach ($this->dependencies as $deplinenr => $dependency) {
      if (!empty($dependency)) {
        $new_var->dependencies[$deplinenr] = $dependency;
      }
    }

    // if $GLOBALS['x'] is used outside a function its the same as using var $x, rewrite
    if ('$GLOBALS' === $var_name && !empty($array_keys) && !$this->in_function) {
      $var_name = '$' . array_shift($array_keys);
    }

    // add additional array keys
    if (!empty($additional_keys)) {
      if (empty($array_keys)) {
        $array_keys[] = $additional_keys;
      }
      else {
        $array_keys = array_merge($array_keys, [$additional_keys]);
      }
    }

    // add/resolve array keys
    if (!empty($array_keys)) {
      foreach ($array_keys as $key) {
        if (!is_array($key)) {
          $new_var->array_keys[] = $key;
        }
        else {
          $recstring = Analyzer::get_tokens_value(
            $this->file_pointer,
            $key,
            $this->in_function ? $this->var_declares_local : $this->var_declares_global,
            $this->var_declares_global,
            $id
          );

          if (!empty($recstring)) {
            $new_var->array_keys[] = $recstring;
          }
          else {
            $new_var->array_keys[] = '*';
          }
        }
      }
    }

    if ($this->in_function) {
      if (!isset($this->var_declares_local[$var_name])) {
        $this->var_declares_local[$var_name] = [$new_var];
      }
      else {
        array_unshift($this->var_declares_local[$var_name], $new_var);
      }

      // if variable was put in global scope, save assignments
      // later they will be pushed to the global var list when function is called
      if (in_array($var_name, $this->put_in_global_scope)) {
        if (!isset($this->globals_from_function[$this->function_obj->name][$var_name])) {
          $this->globals_from_function[$this->function_obj->name][$var_name] = [$new_var];
        }
        else {
          array_unshift($this->globals_from_function[$this->function_obj->name][$var_name], $new_var);
        }
      }
    }
    elseif (!isset($this->var_declares_global[$var_name])) {
      $this->var_declares_global[$var_name] = [$new_var];
    }
    else {
      array_unshift($this->var_declares_global[$var_name], $new_var);
    }
  }

  // scans variable for $$dynamic vars or $dynamic() function calls
  public function variable_scan($i, $offset, $category, $title) {
    if (isset($this->scan_functions[$category])) {
      // build new find
      $new_find = new VulnTreeNode();
      $new_find->name = $category;
      $new_find->lines[] = $this->tokens[$i][2];

      // count sinks
      $GLOBALS['file_sinks_count'][$this->file_pointer]++;

      if ($this->in_function) {
        $GLOBALS['user_functions_offset'][$this->function_obj->name][6]++;
      }
      else {
        $GLOBALS['user_functions_offset']['__main__'][6]++;
      }

      // add dependencies
      foreach ($this->dependencies as $deplinenr => $dependency) {
        if (!empty($dependency)) {
          $new_find->dependencies[$deplinenr] = $dependency;
        }
      }

      // trace back parameters and look for userinput
      $userinput = $this->scan_parameter(
        $new_find,
        $new_find,
        $this->tokens[$i],
        $this->tokens[$i][3],
        $i,
        $this->in_function ? $this->var_declares_local : $this->var_declares_global,
        $this->var_declares_global,
        FALSE,
        []
      );

      // add find to output if function call has variable parameters (With userinput)
      if ($userinput || 4 == $GLOBALS['verbosity']) {
        $new_find->filename = $this->file_pointer;
        $new_find->value = highlightline(array_slice($this->tokens, $i - $offset, $offset + 3 + Analyzer::getBraceEnd($this->tokens, $i + 2)), $this->comment, $this->tokens[$i][2], $this->tokens[$i][1], FALSE, [1]);

        // add to output
        $new_find->title = $title;
        $block = new VulnBlock($this->tif . '_' . $this->tokens[$i][2] . '_' . basename($this->file_pointer), getVulnNodeTitle($category), $this->tokens[$i][1]);
        $block->treenodes[] = $new_find;

        if (1 == $userinput || 4 == $GLOBALS['verbosity']) {
          $block->vuln = TRUE;
          increaseVulnCounter($category);
        }

        $GLOBALS['output'][$this->file_name][] = $block;

        if ($this->in_function) {
          $this->ignore_securing_function = TRUE;
          // mark function in class as vuln
          if ($this->in_class) {
            $this->vuln_classes[$this->class_name][] = $this->function_obj->name;
          }
        }

        // add register_globals implementation
        if ('extract' === $category) {
          $this->variable_add(
            'register_globals',
            array_merge(array_slice($this->tokens, $i - $offset, ($end = $offset + 3 + Analyzer::getBraceEnd($this->tokens, $i + 2))), [
              [
                T_COMMENT,
                '// is like ',
                0,
              ],
              [T_STRING, 'import_request_variables', 0],
              '(',
              ')',
            ]),
            'see above',
            1, $end + 2,
            $this->tokens[$i][2],
            $i,
            $this->tokens[$i][3] ?? []
          );

        }
      }
    }
  }

  // check if same vulnBlock with the same unique identifier has already been scanned
  public function already_scanned($i) {
    $uid = $this->tif . '_' . $this->tokens[$i][2] . '_' . basename($this->file_pointer);
    foreach ($GLOBALS['output'] as $file) {
      foreach ($file as $vulnBlock) {
        if ($vulnBlock->uid == $uid && $vulnBlock->vuln) {
          $vulnBlock->alternatives[] = $this->file_name;
          return TRUE;
        }
      }
    }
    return FALSE;
  }

  // check if securing function is listed as securing that depends on quotes
  public function quote_analysis_needed() {
    foreach ($this->securedby as $var => $func) {
      if (in_array($func, $GLOBALS['F_QUOTE_ANALYSIS'])) {
        return TRUE;
      }
    }
    return FALSE;
  }

  // parse tokens of php file, build program model, follow program flow, initiate taint analysis
  public function parse() {
    // scan all tokens
    for ($i = 0, $tokencount = count($this->tokens); $i < $tokencount; $i++, $this->tif++) {
      if (is_array($this->tokens[$i])) {
        $token_name = $this->tokens[$i][0];
        $token_value = $this->tokens[$i][1];
        $line_nr = $this->tokens[$i][2];

        // add preloader info for big files
        if (0 == $line_nr % PRELOAD_SHOW_LINE) {
          echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . ' (line ' . $line_nr . ')|' . $GLOBALS['timeleft'] . '|' . "\n";

          if (empty($_POST['statnow'])) {
            @ob_flush();
            flush();
          }
        }

        # debug
        #echo "file:".$file_name.",line:".$line_nr.",token:".token_name($token_name).",";
        #echo "value:".htmlentities($token_value).",";
        #echo "in_function:".$in_function.",in_class:".$in_class."<br>";

        /*************************
         * T_VARIABLE
         *************************/
        if (T_VARIABLE === $token_name) {
          // $var()
          if ('(' === $this->tokens[$i + 1][0]) {
            $this->variable_scan($i, 0, 'eval', 'Userinput is used as dynamic function name. Arbitrary functions may be called.');
          }
          // $$var =
          elseif (('$' === $this->tokens[$i - 1] || ('{' === $this->tokens[$i - 1] && '$' === $this->tokens[$i - 2])) && ('=' === $this->tokens[$i + 1] || in_array($this->tokens[$i + 1][0], Tokens::T_ASSIGNMENT))) {
            $this->variable_scan($i, '{' === $this->tokens[$i - 1] ? 2 : 1, 'extract', 'Userinput is used to build the variable name. Arbitrary variables may be overwritten/initialized which may lead to further vulnerabilities.');
          }
          // foreach($var as $key => $value)
          elseif (T_AS === $this->tokens[$i - 1][0]
            || (T_DOUBLE_ARROW === $this->tokens[$i - 1][0] && T_VARIABLE === $this->tokens[$i - 2][0] && T_AS === $this->tokens[$i - 3][0])) {
            $c = 3;
            while (T_FOREACH !== $this->tokens[$i - $c][0]) {
              $c++;

              if (($i - $c) < 0 || ';' === $this->tokens[$i - $c]) {
                addError('Could not find FOREACH token before AS token', array_slice($this->tokens, $i - 5, 10), $this->tokens[$i - 1][2], $this->file_pointer);
                break;
              }
            }

            $this->variable_add(
              $token_value,
              array_slice($this->tokens, $i - $c, $c + Analyzer::getBraceEnd($this->tokens, $i)),
              '',
              0, 0,
              $line_nr,
              $i,
              $this->tokens[$i][3] ?? []
            );
          }
          // for($var=1; ...)	: add whole instruction block to output
          elseif (T_FOR === $this->tokens[$i - 2][0]
            && ('=' === $this->tokens[$i + 1] || in_array($this->tokens[$i + 1][0], Tokens::T_ASSIGNMENT))) {
            $c = 1;
            $newbraceopen = 1;
            $firstsemi = 0;
            // do not use getBraceEnd() here, because we dont want to stop at ';' in for(;;)
            while (0 !== $newbraceopen) {
              // watch function calls in function call
              if ('(' === $this->tokens[$i + $c]) {
                $newbraceopen++;
              }
              elseif (')' === $this->tokens[$i + $c]) {
                $newbraceopen--;
              }
              elseif (';' === $this->tokens[$i + $c] && $firstsemi < 1) {
                $firstsemi = $c;
              }
              $c++;

              if (!isset($this->tokens[$i + $c])) {
                addError('Could not find closing parenthesis of for-statement.', array_slice($this->tokens, $i - 2, 10), $this->tokens[$i - 2][2], $this->file_pointer);
                break;
              }
            }

            // overwrite value of first var because it is looped
            // this is an assumption, other vars could be declared for($var1=1;$var2=2;...)
            $this->tokens[$i + 2][0] = T_ENCAPSED_AND_WHITESPACE;
            $this->tokens[$i + 2][1] = '*';

            $this->variable_add(
              $token_value,
              array_slice($this->tokens, $i - 2, $c + 2),
              '',
              1, 2 + $firstsemi,
              $line_nr,
              $i,
              $this->tokens[$i][3] ?? []
            );
          }
          // $var = ...;
          elseif ('=' === $this->tokens[$i + 1] || in_array($this->tokens[$i + 1][0], Tokens::T_ASSIGNMENT)) {
            $vardeclare = [];

            // $var = array(1,2,3,4);
            if (T_ARRAY === $this->tokens[$i + 2][0] && '(' === $this->tokens[$i + 3] && ')' !== $this->tokens[$i + 4]) {
              $d = 4;
              $keyindex = 0;
              $newbraceopen = 1;
              $keytokens = [];
              $valuetokens = [];

              while (!(0 === $newbraceopen || ';' === $this->tokens[$i + $d])
                && $keyindex < MAX_ARRAY_ELEMENTS) {
                // count parameters
                if (1 === $newbraceopen && (',' === $this->tokens[$i + $d] || ')' === $this->tokens[$i + $d])) {
                  $newindexvar = $this->tokens[$i];
                  $newindexvar[3][] = empty($keytokens) ? $keyindex : $keytokens;

                  $this->variable_add(
                    $token_value,
                    array_merge([
                      $newindexvar,
                      $this->tokens[$i + 1],
                    ], $valuetokens),
                    ' array() ',
                    in_array($this->tokens[$i + 1][0], Tokens::T_ASSIGNMENT) ? 0 : 1, 0,
                    $line_nr,
                    $i,
                    $this->tokens[$i][3] ?? [],
                    empty($keytokens) ? $keyindex : $keytokens
                  );

                  $keyindex++;
                  $keytokens = [];
                  $valuetokens = [];
                }
                // watch function calls in array braces
                elseif ('(' === $this->tokens[$i + $d]) {
                  $newbraceopen++;
                }
                elseif (')' === $this->tokens[$i + $d]) {
                  $newbraceopen--;
                }
                // "=>" detected, tokens before are keyname, next one value
                elseif (T_DOUBLE_ARROW === $this->tokens[$i + $d][0]) {
                  $keytokens = $valuetokens;
                  $valuetokens = [];
                }
                // main
                else {
                  $valuetokens[] = $this->tokens[$i + $d];
                }
                $d++;

                if (!isset($this->tokens[$i + $d])) {
                  addError('Could not find closing parenthesis of array()-declaration.', array_slice($this->tokens, $i, 10), $this->tokens[$i + 2][2], $this->file_pointer);
                  break;
                }
              }
              $vardeclare['end'] = Analyzer::getBraceEnd($this->tokens, $i) + 1;
              // $var = anything;
            }
            else {
              $this->variable_add(
                $token_value,
                array_slice($this->tokens, $i, $vardeclare['end'] = Analyzer::getBraceEnd($this->tokens, $i) + 1),
                '',
                in_array($this->tokens[$i + 1][0], Tokens::T_ASSIGNMENT) ? 0 : 1, 0,
                $line_nr,
                $i,
                $this->tokens[$i][3] ?? []
              );
            }
            // save var and var declare scope for data leak scan
            $vardeclare['start'] = $i;
            $vardeclare['name'] = $token_value;
            $vardeclare['linenr'] = $line_nr;
            $vardeclare['end'] += $i - 1;
          }

          // $class->var
          //else if ($token_name === T_STRING && $tokens[$i-1][0] === T_OBJECT_OPERATOR && $tokens[$i-2][0] === T_VARIABLE)

          // add user input variables to global finding list
          if (in_array($token_value, Sources::$V_USERINPUT)) {
            if (isset($this->tokens[$i][3])) {
              if (!is_array($this->tokens[$i][3][0])) {
                $GLOBALS['user_input'][$token_value . '[' . $this->tokens[$i][3][0] . ']'][$this->file_pointer][] = $line_nr;
              }
              else {
                $GLOBALS['user_input'][$token_value . '[' . Analyzer::get_tokens_value(
                  $this->file_pointer,
                  $this->tokens[$i][3][0],
                  $this->in_function ? $this->var_declares_local : $this->var_declares_global,
                  $this->var_declares_global,
                  $i
                ) . ']'][$this->file_pointer][] = $line_nr;
              }
            }
            else {
              $GLOBALS['user_input'][$token_value][$this->file_pointer][] = $line_nr;
            }

            // count found userinput in function for graphs
            if ($this->in_function) {
              $GLOBALS['user_functions_offset'][$this->function_obj->name][5]++;
            }
            else {
              $GLOBALS['user_functions_offset']['__main__'][5]++;
            }
          }
        }

        // check if token is a function call and a function to scan
        // do not check if next token is '(' because: require $inc; does not use ()
        elseif (in_array($token_name, Tokens::T_FUNCTIONS)
          || (in_array($token_name, Tokens::T_XSS) && ('client' == $_POST['vector'] || 'xss' == $_POST['vector'] || 'all' == $_POST['vector']))) {
          $class = '';
          /*************************
           * T_STRING
           *************************/
          if (T_STRING === $token_name && '(' === $this->tokens[$i + 1]) {
            // define("FOO", $_GET['asd']);
            if ('define' === $token_value) {
              $c = 1;
              while (',' !== $this->tokens[$i + $c]) {
                $c++;

                if (';' === $this->tokens[$i + $c] || !isset($this->tokens[$i + $c])) {
                  addError('Second parameter of define() is missing.', array_slice($this->tokens, $i, $c), $this->tokens[$i][2], $this->file_pointer);
                  break;
                }
              }

              $this->variable_add(
                str_replace(['"', "'"], '', $this->tokens[$i + 2][1]),
                array_slice($this->tokens, $i, Analyzer::getBraceEnd($this->tokens, $i) + 1),
                ' define() ',
                $c, 0,
                $line_nr,
                $i
              );
            }
            // ini_set()
            elseif ('ini_set' === $token_value) {
              $setting = str_replace([
                "'",
                '"',
              ], '', $this->tokens[$i + 2][1]);
              // ini_set('include_path', 'foo/bar')
              if ('include_path' === $setting) {
                $path = Analyzer::get_tokens_value(
                  $this->file_pointer,
                  array_slice($this->tokens, $i + 4, Analyzer::getBraceEnd($this->tokens, $i + 4) + 1),
                  $this->in_function ? $this->var_declares_local : $this->var_declares_global,
                  $this->var_declares_global,
                  $i
                );
                $this->include_paths = array_unique(array_merge($this->include_paths, Analyzer::get_ini_paths($path)));
              }
            }
            // set_include_path('foo/bar')
            elseif ('set_include_path' === $token_value) {
              $path = Analyzer::get_tokens_value(
                $this->file_pointer,
                array_slice($this->tokens, $i + 1, Analyzer::getBraceEnd($this->tokens, $i + 1) + 1),
                $this->in_function ? $this->var_declares_local : $this->var_declares_global,
                $this->var_declares_global,
                $i
              );
              $this->include_paths = array_unique(array_merge($this->include_paths, Analyzer::get_ini_paths($path)));
            }
            // treat error handler as called function
            elseif ('set_error_handler' === $token_value) {
              $token_value = str_replace([
                '"',
                "'",
              ], '', $this->tokens[$i + 2][1]);
            }
            // $array = compact("event", "city");
            elseif ('compact' === $token_value
              && T_VARIABLE === $this->tokens[$i - 2][0]) {
              $f = 2;
              while (')' !== $this->tokens[$i + $f]) {
                // for all array keys save new variable declarations
                if (T_CONSTANT_ENCAPSED_STRING === $this->tokens[$i + $f][0]) {
                  $this->variable_add(
                    $this->tokens[$i - 2][1], [
                    [
                      T_VARIABLE,
                      $this->tokens[$i - 2][1],
                      $line_nr,
                      [
                        str_replace([
                          '"',
                          "'",
                        ], '', $this->tokens[$i + $f][1]),
                      ],
                    ],
                    '=',
                    [
                      T_VARIABLE,
                      '$' . str_replace([
                        '"',
                        "'",
                      ], '', $this->tokens[$i + $f][1]),
                      $line_nr,
                    ],
                    ';',
                  ],
                    ' compact() ',
                    2, 0,
                    $line_nr,
                    $i,
                    $tokens[$i - 2][3],
                    str_replace([
                      '"',
                      "'",
                    ], '', $this->tokens[$i + $f][1])
                  );
                }
                $f++;

                if (';' === $this->tokens[$i + $f] || !isset($this->tokens[$i + $f])) {
                  addError('Closing parenthesis of compact() is missing.', array_slice($this->tokens, $i, $f), $this->tokens[$i][2], $this->file_pointer);
                  break;
                }
              }
            }
            // preg_match($regex, $source, $matches), save $matches as var declare
            elseif ('preg_match' === $token_value || 'preg_match_all' === $token_value) {
              $c = 2;
              $parameter = 1;
              $newbraceopen = 1;

              while (0 !== $newbraceopen) {
                if (is_array($this->tokens[$i + $c])
                  && T_VARIABLE === $this->tokens[$i + $c][0] && 3 == $parameter) {
                  // add variable declaration to beginning of varlist
                  // fake assignment parameter so it will not get traced
                  $this->variable_add(
                    $this->tokens[$i + $c][1],
                    array_slice($this->tokens, $i, Analyzer::getBraceEnd($this->tokens, $i + 2) + 3),
                    ' preg_match() ',
                    0, $c - 1,
                    $this->tokens[$i + $c][2],
                    $i,
                    $this->tokens[$i + $c][3] ?? []
                  );
                }
                // count parameters
                elseif (1 === $newbraceopen && ',' === $this->tokens[$i + $c]) {
                  $parameter++;
                }
                // watch function calls in function call
                elseif ('(' === $this->tokens[$i + $c]) {
                  $newbraceopen++;
                }
                elseif (')' === $this->tokens[$i + $c]) {
                  $newbraceopen--;
                }
                elseif (';' === $this->tokens[$i + $c] || !isset($this->tokens[$i + $c])) {
                  addError('Closing parenthesis of ' . $token_value . '() is missing.', array_slice($this->tokens, $i, $c), $this->tokens[$i][2], $this->file_pointer);
                  break;
                }
                $c++;
              }
            }
            // import_request_variables()
            elseif ('import_request_variables' === $token_value) {
              // add register_globals implementation
              $this->variable_add(
                'register_globals',
                array_slice($this->tokens, $i, Analyzer::getBraceEnd($this->tokens, $i + 1) + 1),
                'register_globals implementation',
                0, 0,
                $line_nr,
                $i,
                $this->tokens[$i][3] ?? []
              );
            }
            // parse_str()
            elseif ('parse_str' === $token_value) {
              $c = 2;
              $parameter = 1;
              $newbraceopen = 1;

              while (0 !== $newbraceopen) {
                if (is_array($this->tokens[$i + $c])
                  && T_VARIABLE === $this->tokens[$i + $c][0] && 2 == $parameter) {
                  // add variable declaration to beginning of varlist
                  // fake assignment parameter so it will not get traced
                  $this->variable_add(
                    $this->tokens[$i + $c][1],
                    array_slice($this->tokens, $i, Analyzer::getBraceEnd($this->tokens, $i + 2) + 3),
                    ' parse_str() ',
                    0, $c - 1,
                    $this->tokens[$i + $c][2],
                    $i,
                    $this->tokens[$i + $c][3] ?? []
                  );
                }
                // count parameters
                elseif (1 === $newbraceopen && ',' === $this->tokens[$i + $c]) {
                  $parameter++;
                }
                // watch function calls in function call
                elseif ('(' === $this->tokens[$i + $c]) {
                  $newbraceopen++;
                }
                elseif (')' === $this->tokens[$i + $c]) {
                  $newbraceopen--;
                }
                elseif (';' === $this->tokens[$i + $c] || !isset($this->tokens[$i + $c])) {
                  addError('Closing parenthesis of ' . $token_value . '() is missing.', array_slice($this->tokens, $i, $c), $this->tokens[$i][2], $this->file_pointer);
                  break;
                }
                $c++;
              }
            }

            //add interesting function calls to info gathering
            if (isset($this->info_functions[$token_value])) {
              $GLOBALS['info'][] = $this->info_functions[$token_value];
            }
            // watch constructor calls $var = Classname($constructor_param);
            elseif (T_NEW !== $this->tokens[$i - 1][0] && isset($this->vuln_classes[$token_value])) {
              $this->class_vars[$this->tokens[$i - 2][1]] = $token_value;
            }
            // add function call to user-defined function list
            else {
              // $classvar->bla()
              if (T_OBJECT_OPERATOR === $this->tokens[$i - 1][0]) {
                $classvar = $this->tokens[$i - 2][1];
                if ('$' !== $classvar[0]) {
                  $classvar = '$' . $classvar;
                }
                $class = ('$this' === $classvar || '$self' === $classvar) ? $this->class_name : $this->class_vars[$classvar];
              }
              // CLASS::func()
              elseif (T_DOUBLE_COLON === $this->tokens[$i - 1][0]) {
                $class = $this->tokens[$i - 2][1];
              }

              // save function call for graph
              if (isset($GLOBALS['user_functions_offset'][($class ? $class . '::' : '') . $token_value])) {
                $GLOBALS['user_functions_offset'][($class ? $class . '::' : '') . $token_value][3][] = [
                  $this->file_pointer,
                  $line_nr,
                ];

                if ($this->in_function) {
                  $GLOBALS['user_functions_offset'][$this->function_obj->name][4][] = $token_value;
                }
                else {
                  $GLOBALS['user_functions_offset']['__main__'][4][] = $token_value;
                }
              }

              // check if token is function call that affects variable scope (global)
              if (isset($this->globals_from_function[$token_value])) {
                // put all previously saved global var assignments to global scope
                foreach ($this->globals_from_function[$token_value] as $var_name => $new_vars) {
                  foreach ($new_vars as $new_var) {
                    $new_var->comment .= " by $token_value()";
                    if (!isset($this->var_declares_global[$var_name])) {
                      $this->var_declares_global[$var_name] = [$new_var];
                    }
                    else {
                      array_unshift($this->var_declares_global[$var_name], $new_var);
                    }
                  }
                }
              }
            }
          }
          /*************************
           * FILE INCLUSION
           *************************/
          // include tokens from included files
          elseif (in_array($token_name, Tokens::T_INCLUDES) && !$this->in_function) {
            $GLOBALS['count_inc']++;
            // include('xxx')
            if ((('(' === $this->tokens[$i + 1]
                && T_CONSTANT_ENCAPSED_STRING === $this->tokens[$i + 2][0]
                && ')' === $this->tokens[$i + 3])
              // include 'xxx'
              || (is_array($this->tokens[$i + 1])
                && T_CONSTANT_ENCAPSED_STRING === $this->tokens[$i + 1][0]
                && ';' === $this->tokens[$i + 2]))) {
              // include('file')
              if ('(' === $this->tokens[$i + 1]) {
                $inc_file = substr($this->tokens[$i + 2][1], 1, -1);
                $skip = 5;
              }
              // include 'file'
              else {
                $inc_file = substr($this->tokens[$i + 1][1], 1, -1);
                $skip = 3;
              }
            }
            // dynamic include
            else {
              $inc_file = Analyzer::get_tokens_value(
                $this->file_pointer,
                array_slice($this->tokens, $i + 1, $c = Analyzer::getBraceEnd($this->tokens, $i + 1) + 1),
                $this->in_function ? $this->var_declares_local : $this->var_declares_global,
                $this->var_declares_global,
                $i
              );

              // in case the get_var_value added several php files, take the first
              $several = explode('.php', $inc_file);
              if (count($several) > 1) {
                $try_file = $several[0] . '.php';
              }

              $skip = $c + 1; // important to save $c+1 here
            }

            $try_file = $inc_file;

            // try absolute include path
            foreach ($this->include_paths as $include_path) {
              if (is_file("$include_path/$try_file")) {
                $try_file = "$include_path/$try_file";
                break;
              }
            }

            // if dirname(__FILE__) appeared it was an absolute path
            if (!is_file($try_file)) {
              // check relativ path
              $try_file = dirname($this->file_name) . '/' . $inc_file;


              if (!is_file($try_file)) {
                $other_try_file = dirname($this->file_pointer) . '/' . $inc_file;

                // if file can not be found check include_path if set
                if (!is_file($other_try_file)) {
                  if (isset($this->include_paths[0])) {
                    foreach ($this->include_paths as $include_path) {
                      if (is_file(dirname($this->file_name) . '/' . $include_path . '/' . $inc_file)) {
                        $try_file = dirname($this->file_name) . '/' . $include_path . '/' . $inc_file;
                        break;
                      }

                      if (is_file(dirname($this->file_pointer) . '/' . $include_path . '/' . $inc_file)) {
                        $try_file = dirname($this->file_pointer) . '/' . $include_path . '/' . $inc_file;
                        break;
                      }
                    }
                  }

                  // if still not a valid file, look a directory above
                  if (!is_file($try_file)) {
                    $try_file = str_replace('\\', '/', $try_file);
                    $pos = strlen($try_file);
                    // replace each found / with /../, start from the end of file name
                    for ($c = 1, $cMax = substr_count($try_file, '/'); $c < $cMax; $c++) {
                      $pos = strrpos(substr($try_file, 1, $pos), '/');
                      if (is_file(substr_replace($try_file, '/../', $pos + 1, 1))) {
                        $try_file = substr_replace($try_file, '/../', $pos + 1, 1);
                        break;
                      }
                    }

                    if (!is_file($try_file)) {
                      $try_file = str_replace('\\', '/', $other_try_file);
                      $pos = strlen($try_file);
                      // replace each found / with /../, start from the end of file name
                      for ($c = 1, $cMax = substr_count($try_file, '/'); $c < $cMax; $c++) {
                        $pos = strrpos(substr($try_file, 1, $pos), '/');
                        if (is_file(substr_replace($try_file, '/../', $pos + 1, 1))) {
                          $try_file = substr_replace($try_file, '/../', $pos + 1, 1);
                          break;
                        }
                      }

                      // if still not a valid file, guess it
                      if (!is_file($try_file)) {
                        $searchfile = basename($try_file);
                        if (FALSE === strpos($searchfile, '$_USERINPUT')) {
                          foreach ($GLOBALS['files'] as $cfile) {
                            if (basename($cfile) == $searchfile) {
                              $try_file = $cfile;
                              break;
                            }
                          }
                        }
                      }

                    }
                  }
                }
                else {
                  $try_file = $other_try_file;
                }
              }
            }

            $try_file_unreal = $try_file;
            $try_file = realpath($try_file);

            // file is valid
            if (!empty($try_file_unreal) && !empty($try_file) && $inc_lines = @$this->file($try_file_unreal)) {
              // file name has not been included
              if (!in_array($try_file, $this->inc_map)) {
                // Tokens
                $tokenizer = new Tokenizer($try_file);
                $inc_tokens = $tokenizer->tokenize(implode('', $inc_lines));
                unset($tokenizer);

                // if(include('file')) { - include tokens after { and not into the condition :S
                if ($this->in_condition) {
                  $this->tokens = array_merge(
                    array_slice($this->tokens, 0, $this->in_condition + 1),  // before include in condition
                    $inc_tokens,                      // included tokens
                    [
                      [
                        Tokens::T_INCLUDE_END,
                        0,
                        1,
                      ],
                    ],            // extra END-identifier
                    array_slice($this->tokens, $this->in_condition + 1)    // after condition
                  );
                }
                else {
                  // insert included tokens in current tokenlist and mark end
                  $this->tokens = array_merge(
                    array_slice($this->tokens, 0, $i + $skip),      // before include
                    $inc_tokens,                    // included tokens
                    [
                      [
                        Tokens::T_INCLUDE_END,
                        0,
                        1,
                      ],
                    ],          // extra END-identifier
                    array_slice($this->tokens, $i + $skip)        // after include
                  );
                }

                $tokencount = count($this->tokens);

                // set lines pointer to included lines, save last pointer
                // (the following tokens will be the included ones)
                $this->lines_stack[] = $inc_lines;
                $this->lines_pointer = end($this->lines_stack);

                // tokennr in file
                $this->tif_stack[] = $this->tif;
                $this->tif = -$skip;

                // set the current file pointer
                $this->file_pointer = $try_file;
                if (!isset($GLOBALS['file_sinks_count'][$this->file_pointer])) {
                  $GLOBALS['file_sinks_count'][$this->file_pointer] = 0;
                }

                echo $GLOBALS['fit'] . '|' . $GLOBALS['file_amount'] . '|' . $this->file_pointer . '|' . $GLOBALS['timeleft'] . '|' . "\n";

                if (empty($_POST['statnow'])) {
                  @ob_flush();
                  flush();
                }

                $this->comment = basename($inc_file);

                $this->inc_file_stack[] = $try_file;

                // build include map for file list
                $this->inc_map[] = $try_file; // all basic includes
              }
            }
            // included file name could not be reversed
            // (probably dynamic with function calls)
            else {
              $GLOBALS['count_inc_fail']++;
              // add information about include error in debug mode
              if (5 == $GLOBALS['verbosity']) {
                // add include command to output
                $found_value = highlightline(array_slice($this->tokens, $i, $skip), $this->comment, $line_nr, $token_value);
                $new_find = new InfoTreeNode($found_value);
                $new_find->lines[] = $line_nr;
                $new_find->filename = $this->file_pointer;
                $new_find->title = 'Include error: tried to include: ' . $try_file_unreal;

                if (isset($GLOBALS['output'][$this->file_name]['inc'])) {
                  $GLOBALS['output'][$this->file_name]['inc']->treenodes[] = $new_find;
                }
                else {
                  $new_block = new VulnBlock($this->tif . '_' . $this->tokens[$i][2] . '_' . basename($this->file_pointer), 'Debug');
                  $new_block->treenodes[] = $new_find;
                  $new_block->vuln = TRUE;
                  $GLOBALS['output'][$this->file_name]['inc'] = $new_block;
                }
              }
            }

          }

          /*************************
           * TAINT ANALYSIS
           *************************/
          if (isset($this->scan_functions[$token_value]) && 5 != $GLOBALS['verbosity']
            // not a function of a class or a function of a vulnerable class
            && (empty($class) || (($this->in_function && is_array($function_obj->parameters) && in_array($classvar, $function_obj->parameters)) || @in_array($token_value, $this->vuln_classes[$class]))) && !$this->already_scanned($i)) {
            // build new find
            $new_find = new VulnTreeNode();
            $new_find->name = $token_value;
            $new_find->lines[] = $line_nr;

            // add dependencies (already here, because checked during var trace
            foreach ($this->dependencies as $deplinenr => $dependency) {
              if (!empty($dependency)) {
                $new_find->dependencies[$deplinenr] = $dependency;
              }
            }

            // count sinks
            $GLOBALS['file_sinks_count'][$this->file_pointer]++;

            if ($this->in_function) {
              $GLOBALS['user_functions_offset'][$this->function_obj->name][6]++;
            }
            else {
              $GLOBALS['user_functions_offset']['__main__'][6]++;
            }

            $parameter = 1;
            $var_counter = 0;
            $vulnparams = [0];
            $has_vuln_parameters = FALSE;
            $parameter_has_userinput = FALSE;
            $parameter_func_depend = FALSE;
            $secured_by_start = FALSE;
            // function calls without quotes (require $inc;) --> no brace count
            $parentheses_open = ('(' === $this->tokens[$i + 1]) ? 1 : -2; // -2: detection of braces doesnt matter
            $parentheses_save = -1;
            $in_securing = FALSE;
            $ignore_securing = FALSE;
            $c = ('(' === $this->tokens[$i + 1]) ? 2 : 1; // important
            $tainted_vars = [];

            $reconstructstr = '';
            $this->securedby = [];

            // get all variables in parameter list between (...)
            // not only until ';' because: system(get($a),$b,strstr($c));
            while (0 !== $parentheses_open && ';' !== $this->tokens[$i + $c]) {
              $this_one_is_secure = FALSE;
              if (is_array($this->tokens[$i + $c])) {
                // scan variables and constants
                if ((T_VARIABLE === $this->tokens[$i + $c][0] && T_OBJECT_OPERATOR !== $this->tokens[$i + $c + 1][0])
                  || (T_STRING === $this->tokens[$i + $c][0] && '(' !== $this->tokens[$i + $c + 1])) {
                  $var_counter++;
                  // scan only potential vulnerable parameters of function call
                  if (in_array($parameter, $this->scan_functions[$token_value][0])
                    || (isset($this->scan_functions[$token_value][0][0])
                      && 0 === $this->scan_functions[$token_value][0][0])) // all parameters accepted
                  {
                    $has_vuln_parameters = TRUE;

                    if ((is_array($this->tokens[$i + $c - 1])
                        && in_array($this->tokens[$i + $c - 1][0], Tokens::T_CASTS))
                      || (is_array($this->tokens[$i + $c + 1])
                        && in_array($this->tokens[$i + $c + 1][0], Tokens::T_ARITHMETIC)) || $in_securing) {
                      $secured_by_start = TRUE;
                      $this_one_is_secure = TRUE;
                    }

                    if ($in_securing && !$ignore_securing) {
                      $this->securedby[] = $securing_function;
                    }

                    // trace back parameters and look for userinput, trace constants globally
                    $userinput = $this->scan_parameter(
                      $new_find,
                      $new_find,
                      $this->tokens[$i + $c],
                      $this->tokens[$i + $c][3],
                      $i + $c,
                      ($this->in_function && '$' === $this->tokens[$i + $c][1][0]) ? $this->var_declares_local : $this->var_declares_global,
                      $this->var_declares_global,
                      FALSE,
                      $this->scan_functions[$token_value][1],
                      FALSE, // no return-scan
                      $ignore_securing,
                      ($this_one_is_secure || $in_securing)
                    );

                    $reconstructstr .= Analyzer::get_var_value(
                      $this->file_pointer,
                      $this->tokens[$i + $c],
                      ($this->in_function && '$' === $this->tokens[$i + $c][1][0]) ? $this->var_declares_local : $this->var_declares_global,
                      $this->var_declares_global,
                      $i + $c,
                      $this->source_functions
                    );


                    if ($userinput /*&& (!$this_one_is_secure || $GLOBALS['verbosity'] == 3)*/) {
                      $vulnparams[] = $parameter;
                      if (1 == $userinput) {
                        $parameter_has_userinput = TRUE;
                      }
                      elseif (2 == $userinput) {
                        $parameter_func_depend = TRUE;
                      }
                      $tainted_vars[] = $var_counter;
                    }
                  }

                  // mark userinput for quote analysis
                  if (in_array($this->tokens[$i + $c][1], Sources::$V_USERINPUT)) {
                    $reconstructstr .= '$_USERINPUT';
                  }
                }
                // userinput from return value of a function
                elseif (T_STRING === $this->tokens[$i + $c][0]
                  && in_array($this->tokens[$i + $c][1], $this->source_functions)
                  // scan only potential vulnerable parameters of function call
                  && (in_array($parameter, $this->scan_functions[$token_value][0])
                    || (isset($this->scan_functions[$token_value][0][0])
                      && 0 === $this->scan_functions[$token_value][0][0])))// all parameters accepted
                {
                  $has_vuln_parameters = TRUE;
                  $parameter_has_userinput = TRUE;
                  $new_find->marker = 1;
                  $reconstructstr .= '$_USERINPUT';
                  $new_find->title = 'Userinput returned by function <i>' . $this->tokens[$i + $c][1] . '</i> reaches sensitive sink';
                  $this->addtriggerfunction($new_find);
                }
                //detect insecuring functions (functions that make previous securing useless)
                elseif (T_STRING === $this->tokens[$i + $c][0]
                  && isset($this->tokens[$i + $c][1]) && in_array($this->tokens[$i + $c][1], $GLOBALS['F_INSECURING_STRING'])
                  && -1 == $parentheses_save) {
                  $parentheses_save = $parentheses_open;
                  $ignore_securing = TRUE;
                }
                // detect securing functions embedded into the sensitive sink
                elseif (!$ignore_securing && (T_STRING === $this->tokens[$i + $c][0]
                    && ((is_array($this->scan_functions[$token_value][1])
                        && in_array($this->tokens[$i + $c][1], $this->scan_functions[$token_value][1]))
                      || in_array($this->tokens[$i + $c][1], $GLOBALS['F_SECURING_STRING'])))
                  || (in_array($this->tokens[$i + $c][0], Tokens::T_CASTS) && '(' === $this->tokens[$i + $c + 1])) {
                  $securing_function = $this->tokens[$i + $c][1];
                  $parentheses_save = $parentheses_open;
                  $in_securing = TRUE;
                  $secured_by_start = TRUE;
                }
                // add strings to reconstructed string for quotes analysis
                elseif (T_CONSTANT_ENCAPSED_STRING === $this->tokens[$i + $c][0]) {
                  $reconstructstr .= substr($this->tokens[$i + $c][1], 1, -1);
                }
                elseif (T_ENCAPSED_AND_WHITESPACE === $this->tokens[$i + $c][0]) {
                  $reconstructstr .= $this->tokens[$i + $c][1];
                }
              }
              // count parameters
              elseif (1 === $parentheses_open && ',' === $this->tokens[$i + $c]) {
                $parameter++;
              }
              // watch function calls in function call
              elseif ('(' === $this->tokens[$i + $c]) {
                $parentheses_open++;
              }
              elseif (')' === $this->tokens[$i + $c]) {
                $parentheses_open--;
                if ($parentheses_open === $parentheses_save) {
                  $parentheses_save = -1;
                  $in_securing = FALSE;
                  $securing_function = '';
                  $ignore_securing = FALSE;
                }
              }
              elseif (!isset($this->tokens[$i + $c])) {
                addError('Closing parenthesis of ' . $token_value . '() is missing.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
                break;
              }
              $c++;
            }

            // quote analysis for securing functions F_QUOTE_ANALYSIS
            // they only protect when return value is embedded into quotes
            if ($this->quote_analysis_needed() && substr_count($reconstructstr, '$_USERINPUT') > 0) {
              // idea: explode on $_USERINPUT and count quotes in SQL query before
              // if not even, then the $_USERINPUT is in an open quote
              $parts = explode('$_USERINPUT', $reconstructstr);
              foreach ($this->securedby as $var => $securefunction) {
                if (in_array($securefunction, $GLOBALS['F_QUOTE_ANALYSIS'])) {
                  // extract the string before the userinput
                  $checkstring = '';
                  $d = 1;
                  foreach ($parts as $part) {
                    $checkstring .= $part;
                    if ($d >= $var) {
                      break;
                    }
                    $d++;
                  }

                  // even amount of quotes (or none) in string
                  // --> no quotes around userinput
                  // --> securing function is	useless
                  if (0 === substr_count($checkstring, "'") % 2
                    && 0 === substr_count($checkstring, '"') % 2) {
                    $has_vuln_parameters = TRUE;
                    $parameter_has_userinput = TRUE;
                    $new_find->title .= "Userinput reaches sensitive sink due to insecure usage of $securefunction() without quotes";
                  }
                }
              }
            }

            // add find to output if function call has variable parameters (With userinput)
            if (($has_vuln_parameters && ($parameter_has_userinput || $parameter_func_depend)) || 4 == $GLOBALS['verbosity'] || isset($this->scan_functions[$token_value][3])) {
              $vulnstart = $i;
              $vulnadd = 1;
              // prepend $var assignment
              if (isset($vardeclare)) {
                $vulnstart = $vardeclare['start'];
                $vulnadd = $vardeclare['end'] - $vardeclare['start'] - $c + 1;//3;
              }
              // prepend echo statement
              elseif (isset($GLOBALS['F_XSS'][$this->tokens[$i - 1][1]])) {
                $vulnstart = $i - 1;
                $vulnadd = 2;
              }
              // prepend class var
              elseif (T_DOUBLE_COLON === $this->tokens[$i - 1][0] || T_OBJECT_OPERATOR === $this->tokens[$i - 1][0]) {
                $vulnstart = $i - 2;
                $vulnadd = 2;
              }

              if (isset($GLOBALS['user_functions'][$this->file_name][$token_value])) {
                $found_line = '<A NAME="' . $token_value . '_call" class="jumplink"></A>';
                $found_line .= highlightline(array_slice($this->tokens, $vulnstart, $c + $vulnadd), $this->comment, $line_nr, FALSE, $token_value);
              }
              else {
                $found_line = highlightline(array_slice($this->tokens, $vulnstart, $c + $vulnadd), $this->comment, $line_nr, $token_value, FALSE, $tainted_vars);
              }

              $new_find->value = $found_line;
              $new_find->filename = $this->file_pointer;

              if ($secured_by_start) {
                $new_find->marker = 2;
              }

              // only show vuln user defined functions
              // if call with userinput has been found
              if (isset($GLOBALS['user_functions'][$this->file_name][$token_value])) {
                $GLOBALS['user_functions'][$this->file_name][$token_value]['called'] = TRUE;
              }

              if ($this->in_function) {
                $this->ignore_securing_function = TRUE;
                // mark function in class as vuln
                if ($this->in_class) {
                  $this->vuln_classes[$this->class_name][] = $this->function_obj->name;
                }
              }

              // putenv with userinput --> getenv is treated as userinput
              if ('putenv' === $token_value) {
                $this->source_functions[] = 'getenv';
                $GLOBALS['source_functions'][] = 'getenv';
                $new_find->title = 'User can set PHP enviroment variables. Adding getenv() to tainting functions';
              }
              elseif ('apache_setenv' === $token_value) {
                $this->source_functions[] = 'apache_getenv';
                $GLOBALS['source_functions'][] = 'apache_getenv';
                $new_find->title = 'User can set Apache enviroment variables. Adding apache_getenv() to tainting functions';
              }
              elseif ('extract' === $token_value || 'parse_str' === $token_value || 'mb_parse_str' === $token_value) {
                // add register_globals implementation
                $this->variable_add(
                  'register_globals',
                  array_slice($this->tokens, $vulnstart, $c + $vulnadd),
                  'register_globals implementation',
                  0, 0,
                  $line_nr,
                  $i,
                  $this->tokens[$i][3] ?? []
                );
              }

              // add to output
              if (isset($GLOBALS['user_functions'][$this->file_name][$token_value])) {
                if (!empty($GLOBALS['output'][$this->file_name])) {
                  foreach ($GLOBALS['output'][$this->file_name] as $block) {
                    $calleesadded = [];
                    foreach ($block->treenodes as $tree) {
                      if ($tree->funcdepend === $token_value
                        && (array_intersect($tree->funcparamdepend, $vulnparams) || isset($this->scan_functions[$token_value][3]))) {
                        // if funcdependend already found and added, just add foundcallee=true and continue
                        // dont add tree again, it is already added to the vulnblock
                        if (in_array($tree->funcdepend, $calleesadded)) {
                          $tree->foundcallee = TRUE;
                          continue;
                        }

                        if (isset($this->scan_functions[$token_value][3])) {
                          $new_find->title = 'Call triggers vulnerability in function <i>' . $token_value . '()</i>';
                        }
                        elseif (empty($new_find->title)) {
                          $new_find->title = 'Userinput is passed through function parameters.';
                        }

                        $block->treenodes[] = $new_find;
                        if (!$block->vuln && ($parameter_has_userinput || isset($this->scan_functions[$token_value][3]) || 4 == $GLOBALS['verbosity'])) {
                          $block->vuln = TRUE;
                          increaseVulnCounter($block->sink);
                        }

                        $tree->foundcallee = TRUE;
                        $calleesadded[] = $token_value;
                      }
                    }
                  }
                  // else: dont use the result
                }
              }
              else {
                if (empty($new_find->title)) {
                  $new_find->title = 'Userinput reaches sensitive sink. For more information, press the help icon on the left side.';
                }
                $block = new VulnBlock($this->tif . '_' . $this->tokens[$i][2] . '_' . basename($this->file_pointer), getVulnNodeTitle($token_value), $token_value);
                $block->treenodes[] = $new_find;
                if ($parameter_has_userinput || 4 == $GLOBALS['verbosity']) {
                  $block->vuln = TRUE;
                  increaseVulnCounter($token_value);
                }
                // if sink in var declare, offer a data leak scan - save infos for that
                if (isset($vardeclare)) {
                  $block->dataleakvar = [
                    $vardeclare['linenr'],
                    $vardeclare['name'],
                  ];
                }

                $GLOBALS['output'][$this->file_name][] = $block;
              }

            }

            // if classvar depends on function parameter, add this parameter to list
            if (isset($this->classvar) && $this->in_function && in_array($this->classvar, $this->function_obj->parameters)) {
              $param = array_search($this->classvar, $this->function_obj->parameters);
              $GLOBALS['user_functions'][$this->file_name][$this->function_obj->name][0][$param] = $param + 1;
            }

          } // taint analysis
        }

        /*************************
         * CONTROL STRUCTURES
         *************************/
        elseif (in_array($token_name, Tokens::T_LOOP_CONTROL)) {
          // ignore in requirements output: while, for, foreach
          // DO..WHILE was rewritten to WHILE in tokenizer
          $this->ignore_requirement = TRUE;

          $c = 1;
          // get variables in loop condition
          while ('{' !== $this->tokens[$i + $c]) {
            if (T_VARIABLE === $this->tokens[$i + $c][0]) {
              $this->tokens[$i + $c][3][] = '*';
            }
            elseif (!isset($this->tokens[$i + $c])) {
              addError('Could not find opening brace after ' . $token_value . '-statement.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
              break;
            }
            $c++;
          }
        }
        // save current dependency
        elseif (in_array($token_name, Tokens::T_FLOW_CONTROL)) {
          $c = 1;
          while ('{' !== $this->tokens[$i + $c]) {
            $c++;
            if (!isset($this->tokens[$i + $c])) {
              addError('Could not find opening brace after ' . $token_value . '-statement.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
              break;
            }
          }
          $this->in_condition = $i + $c;
          $this->dependencytokens = array_slice($this->tokens, $i, $c);
        }

        /*************************
         * FUNCTIONS
         *************************/
        // check if token is a function declaration
        elseif (T_FUNCTION === $token_name) {
          if ($this->in_function) {
            // addError('New function declaration in function declaration of '.$this->function_obj->name.'() found. This is valid PHP syntax but not supported by RIPS now.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
          }
          else {
            $this->in_function++;

            // the next token is the "function name()"
            $i++;
            $function_name = $this->tokens[$i][1] ?? $this->tokens[$i + 1][1];
            $ref_name = ($this->in_class ? $this->class_name . '::' : '') . $function_name;

            // add POP gadgets to info
            if (isset($this->info_functions[$function_name])) {
              $GLOBALS['info'][] = $ref_name;

              // add gadget to output
              $found_line = highlightline(array_slice($this->tokens, $i - 1, 4), $this->comment,
                $line_nr, $function_name, FALSE, $function_name);
              $new_find = new InfoTreeNode($found_line);
              $new_find->title = "POP gadget $ref_name";
              $new_find->lines[] = $line_nr;
              $new_find->filename = $this->file_pointer;

              if (isset($GLOBALS['output'][$this->file_name]['gadgets'])) {
                $GLOBALS['output'][$this->file_name]['gadgets']->treenodes[] = $new_find;
              }
              else {
                $block = new VulnBlock($this->tif . '_' . $this->tokens[$i][2] . '_' . basename($this->file_pointer), 'POP gadgets');
                $block->vuln = TRUE;
                $block->treenodes[] = $new_find;
                $GLOBALS['output'][$this->file_name]['gadgets'] = $block;
              }

            }

            $c = 3;
            while ('{' !== $this->tokens[$i + $c] && ';' !== $this->tokens[$i + $c]) {
              $c++;
            }

            // abstract functions ended
            if (';' === $this->tokens[$i + $c]) {
              $this->in_function--;
            }

            // write to user_functions offset list for referencing in output
            $GLOBALS['user_functions_offset'][$ref_name][0] = $this->file_pointer;
            $GLOBALS['user_functions_offset'][$ref_name][1] = $line_nr - 1;
            // save function as object
            $this->function_obj = new FunctionDeclare($this->dependencytokens = array_slice($this->tokens, $i - 1, $c + 1));
            $this->function_obj->lines[] = $line_nr;
            $this->function_obj->name = $function_name;

            // save all function parameters
            $this->function_obj->parameters = [];
            $e = 1;
            // until function test(...) {
            //  OR
            // interface test { public function test(...); }
            while ('{' !== $this->tokens[$i + $e] && ';' !== $this->tokens[$i + $e]) {
              if (is_array($this->tokens[$i + $e]) && T_VARIABLE === $this->tokens[$i + $e][0]) {
                $this->function_obj->parameters[] = $this->tokens[$i + $e][1];
              }
              $e++;
            }
            // now skip the params from rest of scan,
            // or function test($a=false, $b=false) will be detected as var declaration
            $i += $e - 1; // -1, because '{' must be evaluated again
          }
        }
        // add globaled variables (global $a, $b, $c;) to var list
        elseif (T_GLOBAL === $token_name && $this->in_function) {
          $this->globals_from_function[$this->function_obj->name] = [];

          // get all globaled variables
          $b = 1;
          while (';' !== $this->tokens[$i + $b]) {
            if (T_VARIABLE === $this->tokens[$i + $b][0]) {
              // mark variable as global scope affecting
              $this->put_in_global_scope[] = $this->tokens[$i + $b][1];
              // add variable declaration to beginning of varlist
              $new_var = new VarDeclare([
                [T_GLOBAL, 'global', $line_nr],
                [T_VARIABLE, $this->tokens[$i + $b][1], $line_nr],
                ';',
              ], $this->comment);
              $new_var->line = $line_nr;
              $new_var->id = $i;

              // overwrite old local vars
              $this->var_declares_local[$this->tokens[$i + $b][1]] = [$new_var];
            }
            $b++;
          }
        }
        // watch returns before vuln function gets called
        elseif (T_RETURN === $token_name && 1 == $this->in_function) {
          $GLOBALS['userfunction_taints'] = FALSE;
          $GLOBALS['userfunction_secures'] = FALSE;
          $c = 1;
          // get all variables in parameter list
          while (';' !== $this->tokens[$i + $c]) {
            if (is_array($this->tokens[$i + $c])) {
              if (T_VARIABLE === $this->tokens[$i + $c][0]) {
                // check if returned var is secured --> securing function
                $new_find = new VulnTreeNode();
                $userinput = $this->scan_parameter(
                  $new_find,
                  $new_find,
                  $this->tokens[$i + $c],
                  $this->tokens[$i + $c][3],
                  $i + $c,
                  $this->var_declares_local,
                  $this->var_declares_global,
                  FALSE,
                  $GLOBALS['F_SECURES_ALL'],
                  TRUE
                );

                // add function to securing functions
                // if it returns no userinput/function param
                if ((!$userinput || $GLOBALS['userfunction_secures']) && !$this->ignore_securing_function) {
                  $GLOBALS['F_SECURING_STRING'][] = $this->function_obj->name;
                }

                // add function to userinput functions if userinput
                // is fetched in the function and then returned (userinput == 1)
                if (1 == $userinput || $GLOBALS['userfunction_taints']) {
                  $this->source_functions[] = $this->function_obj->name;
                }
              }
              // add function to securing functions if return value is secured
              elseif (in_array($this->tokens[$i + $c][1], $GLOBALS['F_SECURES_ALL'])
                || in_array($this->tokens[$i + $c][0], Tokens::T_CASTS)) {
                $GLOBALS['F_SECURING_STRING'][] = $this->function_obj->name;
                break;
              }
            }
            $c++;
          }
        }

        /*************************
         * CLASSES
         *************************/
        // check if token is a class declaration
        elseif (T_CLASS === $token_name) {
          $i++;
          $this->class_name = $this->tokens[$i][1];
          $this->vuln_classes[$this->class_name] = [];
          $this->in_class = TRUE;
          $GLOBALS['info'][] = '<font color="red">Code is object-oriented. This is not supported yet and can lead to false negatives.</font>';
        }
        // build list of vars that are associated with a class
        // $var = new Classname()
        elseif (T_NEW === $token_name && T_VARIABLE === $this->tokens[$i - 2][0]) {
          $this->class_vars[$this->tokens[$i - 2][1]] = $this->tokens[$i + 1][1];
        }
        // copy vuln functions from extended classes
        elseif (T_EXTENDS === $token_name && $this->in_class) {
          $this->vuln_classes[$this->class_name] = $this->vuln_classes[$this->tokens[$i + 1][1]];
        }

        /*************************
         * OTHER
         *************************/
        // list($drink, $color, $power) = $info;
        elseif (T_LIST === $token_name) {
          $d = 2;
          while (')' !== $this->tokens[$i + $d] && ';' !== $this->tokens[$i + $d]) {
            $d++;
            if (';' === $this->tokens[$i + $d] || !isset($this->tokens[$i + $d])) {
              addError('Closing parenthesis of list() is missing.', array_slice($this->tokens, $i, 10), $this->tokens[$i][2], $this->file_pointer);
              break;
            }
          }
          $tokenscanstart = 0;
          if ('=' === $this->tokens[$i + $d + 1] || in_array($this->tokens[$i + $d + 1][0], Tokens::T_ASSIGNMENT)) {
            $tokenscanstart = $d + 1;
          }
          $c = 2;
          for ($c = 2; $c < $d; $c++) {
            if (is_array($this->tokens[$i + $c])
              && T_VARIABLE === $this->tokens[$i + $c][0]) {
              $this->variable_add(
                $this->tokens[$i + $c][1],
                array_slice($this->tokens, $i, Analyzer::getBraceEnd($this->tokens, $i) + 1),
                ' list() ',
                $tokenscanstart, 0,
                $this->tokens[$i + $c][2],
                $i,
                $this->tokens[$i + $c][3] ?? []
              );
            }
          }
          $i += $c + 2;
        }
        // switch lines pointer back to original code if included tokens end
        elseif (Tokens::T_INCLUDE_END === $token_name) {
          array_pop($this->lines_stack);
          $this->lines_pointer = end($this->lines_stack);
          array_pop($this->inc_file_stack);
          $this->file_pointer = end($this->inc_file_stack);
          $this->comment = basename($this->file_pointer) == basename($this->file_name) ? '' : basename($this->file_pointer);
          $this->tif = array_pop($this->tif_stack);
        }

      }
      else // token is not an array
      {
        if ('{' === $this->tokens[$i]
          && (')' === $this->tokens[$i - 1] || ':' === $this->tokens[$i - 1] || ';' === $this->tokens[$i - 1] // case x:{ or case x;{
            || (is_array($this->tokens[$i - 1])
              && (T_DO === $this->tokens[$i - 1][0]  // do {
                || T_ELSE === $this->tokens[$i - 1][0] // else {
                || T_STRING === $this->tokens[$i - 1][0] // class bla {
                || T_TRY === $this->tokens[$i - 1][0] // try {
                || T_FINALLY === $this->tokens[$i - 1][0] // finally {
                || T_CATCH === $this->tokens[$i - 1][0])))) // catch{
        {
          // save brace amount at start of function
          if ($this->in_function && $this->brace_save_func < 0) {
            $this->brace_save_func = $this->braces_open;
          }

          // save brace amount at start of class
          if ($this->in_class && $this->brace_save_class < 0) {
            $this->brace_save_class = $this->braces_open;
          }

          $this->in_condition = 0;

          if (empty($e)) {
            if (!$this->ignore_requirement) {
              if (!empty($this->dependencytokens)
                && T_ELSE === $this->dependencytokens[0][0] && T_IF !== $this->dependencytokens[1][0]) {
                $this->dependencytokens = $this->last_dependency;
                $this->dependencytokens[] = [
                  T_ELSE,
                  'else',
                  $this->dependencytokens[0][2],
                ];
              }
            }
            else {
              $this->ignore_requirement = FALSE;
            }

            // add dependency (even push empty dependency on stack, it will get poped again)
            $this->dependencies[$line_nr] = $this->dependencytokens;
            $this->dependencytokens = [];
          }
          else {
            unset($e);
          }

          $this->braces_open++;
        }
        // before block ending "}" there must be a ";" or another "}". otherwise curly syntax
        elseif ('}' === $this->tokens[$i]
          && (';' === $this->tokens[$i - 1] || '}' === $this->tokens[$i - 1] || '{' === $this->tokens[$i - 1])) {
          $this->braces_open--;

          // delete current dependency
          $this->last_dependency = array_pop($this->dependencies);
          $this->dependencytokens = [];

          // end of function found if brace amount = amount before function start
          if ($this->in_function && $this->brace_save_func === $this->braces_open) {
            $ref_name = ($this->in_class ? $this->class_name . '::' : '') . $this->function_obj->name;
            // write ending to user_function list for referencing functions in output
            $GLOBALS['user_functions_offset'][$ref_name][2] = $line_nr;
            // reset vars for next function declaration
            $this->brace_save_func = -1;
            $this->ignore_securing_function = FALSE;
            $this->in_function--;
            $this->function_obj = NULL;
            $this->var_declares_local = [];
            $this->put_in_global_scope = [];
            // load new found vulnerable user functions to current scanlist
            if (isset($GLOBALS['user_functions'][$this->file_name])) {
              $this->scan_functions = array_merge($this->scan_functions, $GLOBALS['user_functions'][$this->file_name]);
            }
          }

          // end of class found
          if ($this->in_class && $this->brace_save_class === $this->braces_open) {
            $this->brace_save_class = -1;
            $this->in_class = FALSE;
          }
        }
      } // token scanned

      // detect if still in a vardeclare, otherwise delete saved infos
      if (isset($vardeclare) && $vardeclare['end'] === $i) {
        unset($vardeclare);
      }

    } // all tokens scanned.

    return $this->inc_map;
  }

  public function file($file_name) {
    static $cache = [];

    if (FALSE !== $fn = realpath($file_name)) {
      $file_name = $fn;
    }

    return $cache[$file_name] ?? $cache[$file_name] = file($file_name);
  }
}
