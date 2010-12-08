PHP_ARG_ENABLE(consistent_hashing,
    [Whether to enable the "consistent_hashing" extension],
    [  --enable-consistent_hashing	Enable "consistent_hashing" extension support])

if test $PHP_CONSISTENT_HASHING != "no"; then
  PHP_SUBST(CONSISTENT_HASHING_SHARED_LIBADD)
  PHP_NEW_EXTENSION(consistent_hashing, consistent_hashing.c, $ext_shared)
fi
