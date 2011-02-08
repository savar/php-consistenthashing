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

#include "php_consistent_hashing.h"


zend_class_entry *php_consistent_hashing_sc_entry;
#define PHP_CONSISTENT_HASHING_SC_NAME "ConsistentHashing"

static HashTable *ht_ch_targets;
static HashTable *ht_ch_targetpoints;

static function_entry php_consistent_hashing_sc_functions[] = {
  PHP_ME(ConsistentHashing, __construct, NULL, ZEND_ACC_PUBLIC)
  PHP_ME(ConsistentHashing, addTarget,   NULL, ZEND_ACC_PUBLIC)
  PHP_ME(ConsistentHashing, getTarget,   NULL, ZEND_ACC_PUBLIC)
  { NULL, NULL, NULL }
};

PHP_MINIT_FUNCTION(consistent_hashing)
{
  zend_class_entry ce;
  INIT_CLASS_ENTRY(ce, PHP_CONSISTENT_HASHING_SC_NAME,
    php_consistent_hashing_sc_functions);

  php_consistent_hashing_sc_entry = zend_register_internal_class(&ce TSRMLS_CC);

  zend_declare_property_null(php_consistent_hashing_sc_entry,
		  "targets_in_request", sizeof("targets_in_request")-1,
		  ZEND_ACC_PRIVATE TSRMLS_CC);
  zend_declare_property_null(php_consistent_hashing_sc_entry,
		  "targetpoints_in_request", sizeof("targetpoints_in_request")-1,
		  ZEND_ACC_PRIVATE TSRMLS_CC);


  ht_ch_targets = pemalloc(sizeof(HashTable), 1);
  ht_ch_targetpoints = pemalloc(sizeof(HashTable), 1);

  if (zend_hash_init(ht_ch_targets, 32, NULL,
        NULL, 1) != SUCCESS) { /* FIXME destructor should be defined and created to cleanup the hash */
    pefree(ht_ch_targets, 1);
    return FAILURE;
  }

  /*
   * initial we expect ~ 3 redis servers with 2 weighted 1 and 1 weighted 2
   * so that with 160 points per weight we get 4*160 points
   */
  if (zend_hash_init(ht_ch_targetpoints, 4*160, NULL,
        NULL, 1) != SUCCESS) { /* FIXME destructor should be defined and created to cleanup the hash */
    pefree(ht_ch_targetpoints, 1);
    return FAILURE;
  }

  return SUCCESS;
}

zend_module_entry consistent_hashing_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
  STANDARD_MODULE_HEADER,
#endif
  PHP_CONSISTENT_HASHING_EXTNAME,
  NULL, /* FUNCTIONS */
  PHP_MINIT(consistent_hashing), /* MINIT */
  NULL, /* MSHUTDOWN */
  NULL, /* RINIT */
  NULL, /* RSHUTDOWN */
  NULL, /* MINFO */
#if ZEND_MODULE_API_NO >= 20010901
  PHP_CONSISTENT_HASHING_EXTVER,
#endif
  STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_CONSISTENT_HASHING
ZEND_GET_MODULE(consistent_hashing)
#endif

PHP_METHOD(ConsistentHashing, __construct)
{
/* Temporary saved targets/points to know
 * if a target was added in a single request so that a ->getTarget() won't
 * return anything if no target was added nor return a target never added in
 * this request but in a previous one
 */
  HashTable *ht_ch_targets_in_request;
  HashTable *ht_ch_targetpoints_in_request;
  zval *object;
  zval *targets_in_request;
  zval *targetpoints_in_request;
  char *propname;
  int propname_len;
  int num_of_elements;

  ht_ch_targets_in_request = emalloc(sizeof(HashTable));
  ht_ch_targetpoints_in_request = emalloc(sizeof(HashTable));

  if (zend_hash_init(ht_ch_targets_in_request, 32, NULL,
        NULL, 1) != SUCCESS) { /* no destructor because the values are persistent whereas the hashtable is not */
    efree(ht_ch_targets_in_request);
    return;
  }

  num_of_elements = zend_hash_num_elements(ht_ch_targetpoints);

  if (num_of_elements == 0)
    num_of_elements = 4*160;

  if (zend_hash_init(ht_ch_targetpoints_in_request, num_of_elements, NULL,
        NULL, 1) != SUCCESS) { /* no destructor because the values are persistent whereas the hashtable is not */
    efree(ht_ch_targetpoints_in_request);
    return;
  }

  MAKE_STD_ZVAL(targets_in_request);
  MAKE_STD_ZVAL(targetpoints_in_request);
  Z_TYPE_P(targets_in_request) = IS_ARRAY;
  Z_TYPE_P(targetpoints_in_request) = IS_ARRAY;

  Z_ARRVAL_P(targets_in_request) = ht_ch_targets_in_request;
  Z_ARRVAL_P(targetpoints_in_request) = ht_ch_targetpoints_in_request;

  object = getThis();

  zend_update_property(php_consistent_hashing_sc_entry,
	object,
	"targets_in_request", sizeof("targets_in_request")-1,
	targets_in_request TSRMLS_CC);

  zval_ptr_dtor(&targets_in_request);

  zend_update_property(php_consistent_hashing_sc_entry,
	object,
	"targetpoints_in_request", sizeof("targetpoints_in_request")-1,
	targetpoints_in_request TSRMLS_CC);

  zval_ptr_dtor(&targetpoints_in_request);
}

PHP_METHOD(ConsistentHashing, addTarget)
{
  HashTable *ht_ch_targets_in_request;
  HashTable *ht_ch_targetpoints_in_request;
  HashPosition position;
  PointTarget *pair;
  zval *object;
  char *target;
  int target_len;
  int weight = 1;

  if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(),
        "Os|l!", &object, php_consistent_hashing_sc_entry, &target, &target_len, &weight) == FAILURE) {
    zend_throw_exception(NULL, "addTarget expects at least one parameter for the target", 0 TSRMLS_CC);
  }

  if (weight < 1) {
    zend_throw_exception(NULL, "weight has to be an integer greater than 0", 0 TSRMLS_CC);
  }

  if (target_len <= 0) {
    zend_throw_exception(NULL, "the target can't be an empty string", 0 TSRMLS_CC);
  }

  ht_ch_targets_in_request      = ht_get_array(object, "targets_in_request");
  ht_ch_targetpoints_in_request = ht_get_array(object, "targetpoints_in_request");

  if (!zend_hash_exists(ht_ch_targets_in_request, target, target_len)) {
    if (!zend_hash_exists(ht_ch_targets, target, target_len)) {
      if (ht_target_init(target, target_len, weight TSRMLS_CC) == FAILURE) {
        /* should never go here */
        RETURN_NULL();
      }

      if (!zend_hash_update(ht_ch_targets, target, target_len, &"d", strlen("d"), NULL) == FAILURE) {
        /* should never go here */
        RETURN_NULL();
      }
    }

    if (!zend_hash_update(ht_ch_targets_in_request, target, target_len, &"d", strlen("d"), NULL) == FAILURE) {
      /* should never go here */
      RETURN_NULL();
    }

    zend_hash_clean(ht_ch_targetpoints_in_request);

    for (zend_hash_internal_pointer_reset_ex(ht_ch_targetpoints, &position);
         zend_hash_has_more_elements_ex(ht_ch_targetpoints, &position) == SUCCESS;
         zend_hash_move_forward_ex(ht_ch_targetpoints, &position)) {
      zend_hash_get_current_data_ex(ht_ch_targetpoints, (void *) &pair, &position);

      if (zend_hash_exists(ht_ch_targets_in_request, pair->target, pair->target_len)) {
        if (zend_hash_next_index_insert(ht_ch_targetpoints_in_request,
              pair, sizeof(PointTarget), NULL) == FAILURE) {
          /* should never go here */
          RETURN_NULL();
        }
      }
    }
  }
}

PHP_METHOD(ConsistentHashing, getTarget)
{
  char *target;
  char *key;
  int key_len;
  uint point;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
        "s", &key, &key_len) == FAILURE) {
    zend_throw_exception(NULL, "getTarget needs a key to search for", 0 TSRMLS_CC);
    RETURN_NULL();
  }

  point = ht_hash_object(key, key_len);

  if ((target = ht_find_target(getThis(), point)) == NULL) {
    RETURN_NULL();
  }

  ZVAL_STRING(return_value, target, 1);
}

PHPAPI char * ht_find_target(zval *object, uint point) {

  HashTable *ht_ch_targets_in_request;
  HashTable *ht_ch_targetpoints_in_request;
  PointTarget *pair;
  int points;
  int targets;
  int lower_point;
  int middle_point;
  int upper_point;
  int actual_point;
  int left_point;
  char *target;

  ht_ch_targets_in_request      = ht_get_array(object, "targets_in_request");
  ht_ch_targetpoints_in_request = ht_get_array(object, "targetpoints_in_request");

  points       = zend_hash_num_elements(ht_ch_targetpoints_in_request);
  targets      = zend_hash_num_elements(ht_ch_targets_in_request);
  lower_point  = 0;
  upper_point  = points;

  if (targets == 0)
    return NULL;

  while(1) {
    middle_point = (lower_point + upper_point) / 2;

    if (middle_point == points) {
      if (zend_hash_index_find(ht_ch_targetpoints_in_request, 0, (void *) &pair) != SUCCESS) {
        zend_error(E_WARNING, "searching in array wasn't successful while trying to obtain the first index");
        return NULL;
      }

      return pair->target;
    }

    if (zend_hash_index_find(ht_ch_targetpoints_in_request, middle_point, (void *) &pair) != SUCCESS) {
      zend_error(E_WARNING, "searching in array wasn't successful while trying to obtain the index %d", middle_point);
      return NULL;
    }

    actual_point = pair->point;
    target       = pair->target;

    if (middle_point == 0)
      left_point = 0;
    else {
      if (zend_hash_index_find(ht_ch_targetpoints_in_request, middle_point - 1, (void *) &pair) != SUCCESS) {
        zend_error(E_WARNING, "searching in array wasn't successful while trying to obtain the index %d", middle_point - 1);
        return NULL;
      }

      left_point = pair->point;
    }

    if (left_point < point && point <= actual_point) {
      return target;
    }

    if (actual_point < point)
      lower_point = middle_point + 1;
    else
      upper_point = middle_point - 1;

    if (lower_point > upper_point) {
      if (zend_hash_index_find(ht_ch_targetpoints_in_request, 0, (void *) &pair) != SUCCESS) {
        zend_error(E_WARNING, "searching in array wasn't successful while trying to obtain the first index");
        return NULL;
      }

      return pair->target;
    }
  }
}

PHPAPI int ht_target_init(char *target, int target_len, long weight TSRMLS_DC)
{
  zval *convert_var;
  PointTarget *pair;
  int i, temp_key_len;
  uint point;
  char *temp_key;

  MAKE_STD_ZVAL(convert_var);
  ZVAL_LONG(convert_var, 160*weight);
  convert_to_string(convert_var);

  /*
   * instead of emalloc in each loop iteration, the maximum size
   * will be allocated and the beginning is always the same
   * key_len + \0 + Z_STRLEN_P(MAXIMUM_LENGTH_OF_INTEGER)
   */
  temp_key_len = target_len + 1 + Z_STRLEN_P(convert_var);
  temp_key = emalloc(temp_key_len);
  memcpy(temp_key, target, target_len);

  for (i=0; i<160*weight; ++i) {
    efree(Z_STRVAL_P(convert_var));

    ZVAL_LONG(convert_var, i);
    convert_to_string(convert_var);

    /* target_len + \0 + Z_STRLEN_P(convert_var)*/
    temp_key_len = target_len + 1 + Z_STRLEN_P(convert_var);
    memcpy(&(temp_key[target_len]), Z_STRVAL_P(convert_var), Z_STRLEN_P(convert_var));
    temp_key[temp_key_len - 1] = 0;

    point = ht_hash_object(temp_key, temp_key_len - 1);
    /* now save a pair of point, target */
    pair = emalloc(sizeof(PointTarget));
    pair->point = point;
    pair->target = pemalloc(target_len + 1, 1);
    pair->target_len = target_len;
    memcpy(pair->target, target, target_len);
    pair->target[target_len] = 0;

    if (zend_hash_next_index_insert(ht_ch_targetpoints,
          pair, sizeof(PointTarget), NULL) == FAILURE) {
      zend_hash_destroy(ht_ch_targetpoints);
      efree(pair);
      efree(temp_key);
      efree(convert_var);
      return FAILURE;
    }

    efree(pair);
  }

  efree(Z_STRVAL_P(convert_var));
  efree(temp_key);
  efree(convert_var);

  if (zend_hash_sort(ht_ch_targetpoints, zend_qsort, (compare_func_t) ht_compare_targetpoints, 1 TSRMLS_CC) == FAILURE) {
    return FAILURE;
  }

  return SUCCESS;
}

static int ht_compare_targetpoints(void *a, void *b TSRMLS_DC) {
  Bucket *f;
  Bucket *s;
  PointTarget *left;
  PointTarget *right;

  f = *((Bucket **) a);
  s = *((Bucket **) b);

  left  = (PointTarget *) f->pData;
  right = (PointTarget *) s->pData;

  if (left->point < right->point)
    return -1;
  else if (left->point == right->point)
    return strcmp(left->target, right->target);

  return 1;
}

PHPAPI uint ht_hash_object(char *object, int object_len) {
  PHP_MD5_CTX context;
  char digest[16];
  char hexdigest[33];

  PHP_MD5Init(&context);
  PHP_MD5Update(&context, object, object_len);
  PHP_MD5Final(digest, &context);
  make_digest(hexdigest, digest);

  return (hexdigest[0] << 23 | hexdigest[1] << 16 | hexdigest[2] << 8 | hexdigest[3]);
}

PHPAPI HashTable * ht_get_array(zval *object, char *name TSRMLS_DC) {
  HashTable *ht;
  zval *property;

  property = zend_read_property(
      php_consistent_hashing_sc_entry,
      object,
      name, strlen(name), 0);


  ht = Z_ARRVAL_P(property);

  return ht;
}
