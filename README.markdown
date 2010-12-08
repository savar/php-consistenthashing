PhpConsistentHashing
=============
This extension provides a simple class for consistent hashing.

This code is maintained by [Simon Effenberg](http://github.com/Savar).
You can send comments, patches, questions here on github.

Installing/Configuring
======================

<pre>
phpize
./configure
make && make install
</pre>

or as debian package

<pre>
dpkg-buildpackage
</pre>

This extension exports a single class, `ConsistentHashing`.

Error handling
==============

php-consistenthashing throws an `Exception` if invalid parameters will be passed to the functions

Methods
=========

## ConsistentHashing::__construct
##### *Description*

Creates a ConsistentHashing object

##### *Example*

$ch = new ConsistentHashing();

## addTarget
##### *Description*

adds a target to the internal ring structure where the `weight` parameter
determines if the target should be found more often

##### *Parameters*

*target*: string  
*weight*: int (optional, default is 1 and should be 1 or greater)

##### *Example*

<pre>
$ch->addTarget('myhost1');
$ch->addTarget('myhost2', 2);
</pre>

## getTarget
##### *Description*

Get the target (added with `addTarget`) the specified key should be on.

##### *Parameters*

*key*: string

##### *Return Value*

*String* or *NULL*: If no target exists (because addTarget wasn't called), `NULL` is returned. Otherwise, the target related to this key is returned.

##### *Examples*

<pre>
$ch->getTarget('key');
</pre>

