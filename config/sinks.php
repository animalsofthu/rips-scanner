<?php
/**
 *
 * RIPS - A static source code analyser for vulnerabilities in PHP scripts
 * by Johannes Dahse (johannes.dahse@rub.de)
 *
 *
 * Copyright (C) 2012 Johannes Dahse
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


// cross-site scripting affected functions
// parameter = 0 means, all parameters will be traced
$NAME_XSS = 'Cross-Site Scripting';
$F_XSS = [
  'echo'               => [[0], $F_SECURING_XSS],
  'print'              => [[1], $F_SECURING_XSS],
  'print_r'            => [[1], $F_SECURING_XSS],
  'exit'               => [[1], $F_SECURING_XSS],
  'die'                => [[1], $F_SECURING_XSS],
  'printf'             => [[0], $F_SECURING_XSS],
  'vprintf'            => [[0], $F_SECURING_XSS],
  'trigger_error'      => [[1], $F_SECURING_XSS],
  'user_error'         => [[1], $F_SECURING_XSS],
  'odbc_result_all'    => [[2], $F_SECURING_XSS],
  'ovrimos_result_all' => [[2], $F_SECURING_XSS],
  'ifx_htmltbl_result' => [[2], $F_SECURING_XSS],
];

// HTTP header injections
$NAME_HTTP_HEADER = 'HTTP Response Splitting';
$F_HTTP_HEADER = [
  'header' => [[1], []],
];

// session fixation
$NAME_SESSION_FIXATION = 'Session Fixation';
$F_SESSION_FIXATION = [
  'setcookie'    => [[2], []],
  'setrawcookie' => [[2], []],
  'session_id'   => [[1], []],
];

// code evaluating functions  => (parameters to scan, securing functions)
// example parameter array(1,3) will trace only first and third parameter
$NAME_CODE = 'Code Execution';
$F_CODE = [
  'assert'                => [[1], []],
  'create_function'       => [[1, 2], []],
  'eval'                  => [[1], []],
  'mb_ereg_replace'       => [[1, 2], $F_SECURING_PREG],
  'mb_eregi_replace'      => [[1, 2], $F_SECURING_PREG],
  'preg_filter'           => [[1, 2], $F_SECURING_PREG],
  'preg_replace'          => [[1, 2], $F_SECURING_PREG],
  'preg_replace_callback' => [[1], $F_SECURING_PREG],
];

// reflection injection
$NAME_REFLECTION = 'Reflection Injection';
$F_REFLECTION = [
  'event_buffer_new'           => [[2, 3, 4], []],
  'event_set'                  => [[4], []],
  'iterator_apply'             => [[2], []],
  'forward_static_call'        => [[1], []],
  'forward_static_call_array'  => [[1], []],
  'call_user_func'             => [[1], []],
  'call_user_func_array'       => [[1], []],
  'array_diff_uassoc'          => [[3], []],
  'array_diff_ukey'            => [[3], []],
  'array_filter'               => [[2], []],
  'array_intersect_uassoc'     => [[3], []],
  'array_intersect_ukey'       => [[3], []],
  'array_map'                  => [[1], []],
  'array_reduce'               => [[2], []],
  'array_udiff'                => [[3], []],
  'array_udiff_assoc'          => [[3], []],
  'array_udiff_uassoc'         => [[3, 4], []],
  'array_uintersect'           => [[3], []],
  'array_uintersect_assoc'     => [[3], []],
  'array_uintersect_uassoc'    => [[3, 4], []],
  'array_walk'                 => [[2], []],
  'array_walk_recursive'       => [[2], []],
  'assert_options'             => [[2], []],
  'ob_start'                   => [[1], []],
  'register_shutdown_function' => [[1], []],
  'register_tick_function'     => [[1], []],
  'runkit_method_add'          => [[1, 2, 3, 4], []],
  'runkit_method_copy'         => [[1, 2, 3], []],
  'runkit_method_redefine'     => [[1, 2, 3, 4], []],
  'runkit_method_rename'       => [[1, 2, 3], []],
  'runkit_function_add'        => [[1, 2, 3], []],
  'runkit_function_copy'       => [[1, 2], []],
  'runkit_function_redefine'   => [[1, 2, 3], []],
  'runkit_function_rename'     => [[1, 2], []],
  'session_set_save_handler'   => [[1, 2, 3, 4, 5], []],
  'set_error_handler'          => [[1], []],
  'set_exception_handler'      => [[1], []],
  'spl_autoload'               => [[1], []],
  'spl_autoload_register'      => [[1], []],
  'sqlite_create_aggregate'    => [[2, 3, 4], []],
  'sqlite_create_function'     => [[2, 3], []],
  'stream_wrapper_register'    => [[2], []],
  'uasort'                     => [[2], []],
  'uksort'                     => [[2], []],
  'usort'                      => [[2], []],
  'yaml_parse'                 => [[4], []],
  'yaml_parse_file'            => [[4], []],
  'yaml_parse_url'             => [[4], []],
  'eio_busy'                   => [[3], []],
  'eio_chmod'                  => [[4], []],
  'eio_chown'                  => [[5], []],
  'eio_close'                  => [[3], []],
  'eio_custom'                 => [[1, 2], []],
  'eio_dup2'                   => [[4], []],
  'eio_fallocate'              => [[6], []],
  'eio_fchmod'                 => [[4], []],
  'eio_fchown'                 => [[5], []],
  'eio_fdatasync'              => [[3], []],
  'eio_fstat'                  => [[3], []],
  'eio_fstatvfs'               => [[3], []],
  'preg_replace_callback'      => [[2], []],
  'dotnet_load'                => [[1], []],
];

// file inclusion functions => (parameters to scan, securing functions)
$NAME_FILE_INCLUDE = 'File Inclusion';
$F_FILE_INCLUDE = [
  'include'               => [[1], $F_SECURING_FILE],
  'include_once'          => [[1], $F_SECURING_FILE],
  'parsekit_compile_file' => [[1], $F_SECURING_FILE],
  'php_check_syntax'      => [[1], $F_SECURING_FILE],
  'require'               => [[1], $F_SECURING_FILE],
  'require_once'          => [[1], $F_SECURING_FILE],
  'runkit_import'         => [[1], $F_SECURING_FILE],
  'set_include_path'      => [[1], $F_SECURING_FILE],
  'virtual'               => [[1], $F_SECURING_FILE],
];

// file affecting functions  => (parameters to scan, securing functions)
// file handler functions like fopen() are added as parameter
// for functions that use them like fread() and fwrite()
$NAME_FILE_READ = 'File Disclosure';
$F_FILE_READ = [
  'bzread'                  => [[1], $F_SECURING_FILE],
  'bzflush'                 => [[1], $F_SECURING_FILE],
  'dio_read'                => [[1], $F_SECURING_FILE],
  'eio_readdir'             => [[1], $F_SECURING_FILE],
  'fdf_open'                => [[1], $F_SECURING_FILE],
  'file'                    => [[1], $F_SECURING_FILE],
  'file_get_contents'       => [[1], $F_SECURING_FILE],
  'finfo_file'              => [[1, 2], []],
  'fflush'                  => [[1], $F_SECURING_FILE],
  'fgetc'                   => [[1], $F_SECURING_FILE],
  'fgetcsv'                 => [[1], $F_SECURING_FILE],
  'fgets'                   => [[1], $F_SECURING_FILE],
  'fgetss'                  => [[1], $F_SECURING_FILE],
  'fread'                   => [[1], $F_SECURING_FILE],
  'fpassthru'               => [[1, 2], []],
  'fscanf'                  => [[1], $F_SECURING_FILE],
  'ftok'                    => [[1], $F_SECURING_FILE],
  'get_meta_tags'           => [[1], $F_SECURING_FILE],
  'glob'                    => [[1], []],
  'gzfile'                  => [[1], $F_SECURING_FILE],
  'gzgetc'                  => [[1], $F_SECURING_FILE],
  'gzgets'                  => [[1], $F_SECURING_FILE],
  'gzgetss'                 => [[1], $F_SECURING_FILE],
  'gzread'                  => [[1], $F_SECURING_FILE],
  'gzpassthru'              => [[1], $F_SECURING_FILE],
  'highlight_file'          => [[1], $F_SECURING_FILE],
  'imagecreatefrompng'      => [[1], $F_SECURING_FILE],
  'imagecreatefromjpg'      => [[1], $F_SECURING_FILE],
  'imagecreatefromgif'      => [[1], $F_SECURING_FILE],
  'imagecreatefromgd2'      => [[1], $F_SECURING_FILE],
  'imagecreatefromgd2part'  => [[1], $F_SECURING_FILE],
  'imagecreatefromgd'       => [[1], $F_SECURING_FILE],
  'opendir'                 => [[1], $F_SECURING_FILE],
  'parse_ini_file'          => [[1], $F_SECURING_FILE],
  'php_strip_whitespace'    => [[1], $F_SECURING_FILE],
  'readfile'                => [[1], $F_SECURING_FILE],
  'readgzfile'              => [[1], $F_SECURING_FILE],
  'readlink'                => [[1], $F_SECURING_FILE],
  //'stat'						=> array(array(1), array()),
  'scandir'                 => [[1], $F_SECURING_FILE],
  'show_source'             => [[1], $F_SECURING_FILE],
  'simplexml_load_file'     => [[1], $F_SECURING_FILE],
  'stream_get_contents'     => [[1], $F_SECURING_FILE],
  'stream_get_line'         => [[1], $F_SECURING_FILE],
  'xdiff_file_bdiff'        => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_bpatch'       => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_diff_binary'  => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_diff'         => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_merge3'       => [[1, 2, 3], $F_SECURING_FILE],
  'xdiff_file_patch_binary' => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_patch'        => [[1, 2], $F_SECURING_FILE],
  'xdiff_file_rabdiff'      => [[1, 2], $F_SECURING_FILE],
  'yaml_parse_file'         => [[1], $F_SECURING_FILE],
  'zip_open'                => [[1], $F_SECURING_FILE],
];

// file or file system affecting functions
$NAME_FILE_AFFECT = 'File Manipulation';
$F_FILE_AFFECT = [
  'bzwrite'                 => [[2], []],
  'chmod'                   => [[1], $F_SECURING_FILE],
  'chgrp'                   => [[1], $F_SECURING_FILE],
  'chown'                   => [[1], $F_SECURING_FILE],
  'copy'                    => [[1], []],
  'dio_write'               => [[1, 2], []],
  'eio_chmod'               => [[1], $F_SECURING_FILE],
  'eio_chown'               => [[1], $F_SECURING_FILE],
  'eio_mkdir'               => [[1], $F_SECURING_FILE],
  'eio_mknod'               => [[1], $F_SECURING_FILE],
  'eio_rmdir'               => [[1], $F_SECURING_FILE],
  'eio_write'               => [[1, 2], []],
  'eio_unlink'              => [[1], $F_SECURING_FILE],
  'error_log'               => [[3], $F_SECURING_FILE],
  'event_buffer_write'      => [[2], []],
  'file_put_contents'       => [[1, 2], $F_SECURING_FILE],
  'fputcsv'                 => [[1, 2], $F_SECURING_FILE],
  'fputs'                   => [[1, 2], $F_SECURING_FILE],
  'fprintf'                 => [[0], []],
  'ftruncate'               => [[1], $F_SECURING_FILE],
  'fwrite'                  => [[1, 2], $F_SECURING_FILE],
  'gzwrite'                 => [[1, 2], []],
  'gzputs'                  => [[1, 2], []],
  'loadXML'                 => [[1], []],
  'mkdir'                   => [[1], []],
  'move_uploaded_file'      => [[1, 2], $F_SECURING_FILE],
  'posix_mknod'             => [[1], $F_SECURING_FILE],
  'recode_file'             => [[2, 3], $F_SECURING_FILE],
  'rename'                  => [[1, 2], $F_SECURING_FILE],
  'rmdir'                   => [[1], $F_SECURING_FILE],
  'shmop_write'             => [[2], []],
  'touch'                   => [[1], $F_SECURING_FILE],
  'unlink'                  => [[1], $F_SECURING_FILE],
  'vfprintf'                => [[0], []],
  'xdiff_file_bdiff'        => [[3], $F_SECURING_FILE],
  'xdiff_file_bpatch'       => [[3], $F_SECURING_FILE],
  'xdiff_file_diff_binary'  => [[3], $F_SECURING_FILE],
  'xdiff_file_diff'         => [[3], $F_SECURING_FILE],
  'xdiff_file_merge3'       => [[4], $F_SECURING_FILE],
  'xdiff_file_patch_binary' => [[3], $F_SECURING_FILE],
  'xdiff_file_patch'        => [[3], $F_SECURING_FILE],
  'xdiff_file_rabdiff'      => [[3], $F_SECURING_FILE],
  'yaml_emit_file'          => [[1, 2], $F_SECURING_FILE],
];

// OS Command executing functions => (parameters to scan, securing functions)
$NAME_EXEC = 'Command Execution';
$F_EXEC = [
  'backticks'                => [[1], $F_SECURING_SYSTEM],
  # transformed during parsing
  'exec'                     => [[1], $F_SECURING_SYSTEM],
  'expect_popen'             => [[1], $F_SECURING_SYSTEM],
  'passthru'                 => [[1], $F_SECURING_SYSTEM],
  'pcntl_exec'               => [[1], $F_SECURING_SYSTEM],
  'popen'                    => [[1], $F_SECURING_SYSTEM],
  'proc_open'                => [[1], $F_SECURING_SYSTEM],
  'shell_exec'               => [[1], $F_SECURING_SYSTEM],
  'system'                   => [[1], $F_SECURING_SYSTEM],
  'mail'                     => [[5], []],
  // http://esec-pentest.sogeti.com/web/using-mail-remote-code-execution
  'mb_send_mail'             => [[5], []],
  'w32api_invoke_function'   => [[1], []],
  'w32api_register_function' => [[2], []],
];

// SQL executing functions => (parameters to scan, securing functions)
$NAME_DATABASE = 'SQL Injection';
$F_DATABASE = [
  // Abstraction Layers
  'dba_open'                => [[1], []],
  'dba_popen'               => [[1], []],
  'dba_insert'              => [[1, 2], []],
  'dba_fetch'               => [[1], []],
  'dba_delete'              => [[1], []],
  'dbx_query'               => [[2], $F_SECURING_SQL],
  'odbc_do'                 => [[2], $F_SECURING_SQL],
  'odbc_exec'               => [[2], $F_SECURING_SQL],
  'odbc_execute'            => [[2], $F_SECURING_SQL],
  // Vendor Specific
  'db2_exec'                => [[2], $F_SECURING_SQL],
  'db2_execute'             => [[2], $F_SECURING_SQL],
  'fbsql_db_query'          => [[2], $F_SECURING_SQL],
  'fbsql_query'             => [[1], $F_SECURING_SQL],
  'ibase_query'             => [[2], $F_SECURING_SQL],
  'ibase_execute'           => [[1], $F_SECURING_SQL],
  'ifx_query'               => [[1], $F_SECURING_SQL],
  'ifx_do'                  => [[1], $F_SECURING_SQL],
  'ingres_query'            => [[2], $F_SECURING_SQL],
  'ingres_execute'          => [[2], $F_SECURING_SQL],
  'ingres_unbuffered_query' => [[2], $F_SECURING_SQL],
  'msql_db_query'           => [[2], $F_SECURING_SQL],
  'msql_query'              => [[1], $F_SECURING_SQL],
  'msql'                    => [[2], $F_SECURING_SQL],
  'mssql_query'             => [[1], $F_SECURING_SQL],
  'mssql_execute'           => [[1], $F_SECURING_SQL],
  'mysql_db_query'          => [[2], $F_SECURING_SQL],
  'mysql_query'             => [[1], $F_SECURING_SQL],
  'mysql_unbuffered_query'  => [[1], $F_SECURING_SQL],
  'mysqli_stmt_execute'     => [[1], $F_SECURING_SQL],
  'mysqli_query'            => [[2], $F_SECURING_SQL],
  'mysqli_real_query'       => [[1], $F_SECURING_SQL],
  'mysqli_master_query'     => [[2], $F_SECURING_SQL],
  'oci_execute'             => [[1], []],
  'ociexecute'              => [[1], []],
  'ovrimos_exec'            => [[2], $F_SECURING_SQL],
  'ovrimos_execute'         => [[2], $F_SECURING_SQL],
  'ora_do'                  => [[2], []],
  'ora_exec'                => [[1], []],
  'pg_query'                => [[2], $F_SECURING_SQL],
  'pg_send_query'           => [[2], $F_SECURING_SQL],
  'pg_send_query_params'    => [[2], $F_SECURING_SQL],
  'pg_send_prepare'         => [[3], $F_SECURING_SQL],
  'pg_prepare'              => [[3], $F_SECURING_SQL],
  'sqlite_open'             => [[1], $F_SECURING_SQL],
  'sqlite_popen'            => [[1], $F_SECURING_SQL],
  'sqlite_array_query'      => [[1, 2], $F_SECURING_SQL],
  'arrayQuery'              => [[1, 2], $F_SECURING_SQL],
  'singleQuery'             => [[1], $F_SECURING_SQL],
  'sqlite_query'            => [[1, 2], $F_SECURING_SQL],
  'sqlite_exec'             => [[1, 2], $F_SECURING_SQL],
  'sqlite_single_query'     => [[2], $F_SECURING_SQL],
  'sqlite_unbuffered_query' => [[1, 2], $F_SECURING_SQL],
  'sybase_query'            => [[1], $F_SECURING_SQL],
  'sybase_unbuffered_query' => [[1], $F_SECURING_SQL],
];

// xpath injection
$NAME_XPATH = 'XPath Injection';
$F_XPATH = [
  'xpath_eval'            => [[2], $F_SECURING_XPATH],
  'xpath_eval_expression' => [[2], $F_SECURING_XPATH],
  'xptr_eval'             => [[2], $F_SECURING_XPATH],
];

// ldap injection
$NAME_LDAP = 'LDAP Injection';
$F_LDAP = [
  'ldap_add'    => [[2, 3], $F_SECURING_LDAP],
  'ldap_delete' => [[2], $F_SECURING_LDAP],
  'ldap_list'   => [[3], $F_SECURING_LDAP],
  'ldap_read'   => [[3], $F_SECURING_LDAP],
  'ldap_search' => [[3], $F_SECURING_LDAP],
];

// connection handling functions
$NAME_CONNECT = 'Protocol Injection';
$F_CONNECT = [
  'curl_setopt'          => [[2, 3], []],
  'curl_setopt_array'    => [[2], []],
  'cyrus_query'          => [[2], []],
  'error_log'            => [[3], []],
  'fsockopen'            => [[1], []],
  'ftp_chmod'            => [[2, 3], []],
  'ftp_exec'             => [[2], []],
  'ftp_delete'           => [[2], []],
  'ftp_fget'             => [[3], []],
  'ftp_get'              => [[2, 3], []],
  'ftp_nlist'            => [[2], []],
  'ftp_nb_fget'          => [[3], []],
  'ftp_nb_get'           => [[2, 3], []],
  'ftp_nb_put'           => [[2], []],
  'ftp_put'              => [[2, 3], []],
  'get_headers'          => [[1], []],
  'imap_open'            => [[1], []],
  'imap_mail'            => [[1], []],
  'mail'                 => [[1, 4], []],
  'mb_send_mail'         => [[1, 4], []],
  'ldap_connect'         => [[1], []],
  'msession_connect'     => [[1], []],
  'pfsockopen'           => [[1], []],
  'session_register'     => [[0], []],
  'socket_bind'          => [[2], []],
  'socket_connect'       => [[2], []],
  'socket_send'          => [[2], []],
  'socket_write'         => [[2], []],
  'stream_socket_client' => [[1], []],
  'stream_socket_server' => [[1], []],
  'printer_open'         => [[1], []],
];

// other critical functions
$NAME_OTHER = 'Possible Flow Control'; // :X
$F_OTHER = [
  'dl'                       => [[1], []],
  'ereg'                     => [[2], []], # nullbyte injection affected
  'eregi'                    => [[2], []], # nullbyte injection affected
  'ini_set'                  => [[1, 2], []],
  'ini_restore'              => [[1], []],
  'runkit_constant_redefine' => [[1, 2], []],
  'runkit_method_rename'     => [[1, 2, 3], []],
  'sleep'                    => [[1], []],
  'usleep'                   => [[1], []],
  'extract'                  => [[1], []],
  'mb_parse_str'             => [[1], []],
  'parse_str'                => [[1], []],
  'putenv'                   => [[1], []],
  'set_include_path'         => [[1], []],
  'apache_setenv'            => [[1, 2], []],
  'define'                   => [[1], []],
  'is_a'                     => [[1], []] // calls __autoload()
];

// property oriented programming with unserialize
$NAME_POP = 'PHP Object Injection';
$F_POP = [
  'unserialize' => [[1], []], // calls gadgets
  'yaml_parse'  => [[1], []]   // calls unserialize
];

// XML
//simplexml_load_string


# interruption vulnerabilities
# trim(), rtrim(), ltrim(), explode(), strchr(), strstr(), substr(), chunk_split(), strtok(), addcslashes(), str_repeat() htmlentities() htmlspecialchars(), unset()
