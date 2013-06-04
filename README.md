Shardpile maintains a database of SHA1 hashes of a tree in the file system and
allows to verify trees against this hash database.

You can use this for example to verify mirrored data.

Tutorial
========

Assume you have a file system mounted in `/Volume/master` and a mirror of this
file system mounted in `/Volumes/mirror`. Then you can use Shardpile to verify
this mirror.

First the hash database has to be generated:
```
shardpile.py -u /Volumes/master
```
With the same command the database can be updated when files in `/Volume/master`
have been changed. Shardpile will only recalculate the hash of files with
a changed modification time or size.

To verify the contents of `/Volumes/mirror`
```
shardpile.py /Volumes/mirror
```
is used.

In case you want to use a location for the hash database different from the
default `~/.shardpile.db` use the '-d <path>' option.


Requirements
============

* [Python 2.7](http://www.python.org/)
* [gdbm module](http://docs.python.org/2/library/gdbm.html)

For the unit tests, additionally:
* [mock](http://www.voidspace.org.uk/python/mock/)

Installation
============

Just copy shardpile.py to a directory in your search path and make it
executable.


License
=======

The MIT License (see `LICENSE` for details).
