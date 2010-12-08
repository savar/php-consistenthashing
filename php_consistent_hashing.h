/* -*- Mode: C; tab-width: 4 -*- */
/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2009 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Simon Effenberg <savar@schuldeigen.de>                       |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_CONSISTENT_HASHING_H
#define PHP_CONSISTENT_HASHING_H

#define PHP_CONSISTENT_HASHING_EXTNAME "Consistent_Hashing"
#define PHP_CONSISTENT_HASHING_EXTVER "0.1"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/md5.h"

/* structures */
typedef struct point_target {
  uint point;
  char *target;
  int target_len;
} PointTarget;

/* Methods */
PHP_METHOD(ConsistentHashing, addTarget);
PHP_METHOD(ConsistentHashing, getTarget);

/* Internal methods */
PHPAPI int ht_target_init(char *target, int target_len, long weight TSRMLS_DC);
PHPAPI char * ht_find_target(uint point);
PHPAPI uint ht_hash_object(char *object, int object_len);
static int ht_compare_targetpoints(void *a, void *b TSRMLS_DC);

extern zend_module_entry consistent_hashing_module_entry;
#define phpext_consistent_hashing_ptr &consistent_hashing_module_entry

#endif /* PHP_CONSISTENT_HASHING_H */
