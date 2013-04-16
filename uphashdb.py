#!/usr/bin/env python

import collections
import gdbm
import hashlib
import os
import os.path


def sha1sum(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        h.update(f.read(1024 * 1024))
    return h.hexdigest()


class HashDb(collections.MutableMapping):
    class Entry(object):
        __slots__ = ('modification', 'size', 'sha1')

        def __init__(self, modification, size, sha1):
            self.modification = int(modification)
            self.size = int(size)
            self.sha1 = str(sha1)

        @classmethod
        def from_raw_string(cls, raw):
            modification, size, sha1 = raw.split(';')
            return cls(modification, size, sha1)

        @classmethod
        def from_path(cls, path):
            modification = os.path.getmtime(path)
            size = os.path.getsize(path)
            sha1 = sha1sum(path)
            return cls(modification, size, sha1)

        def as_raw_string(self):
            return ';'.join((str(self.modification), str(self.size), self.sha1))

    def __init__(self, filename):
        self.db = gdbm.open(filename, 'cf')

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.sync()

    def __delitem__(self, path):
        del self.db[self.__key_from_path(path)]

    def __getitem__(self, path):
        key = self.__key_from_path(path)
        return HashDb.Entry.from_raw_string(self.db[key])

    def __iter__(self):
        key = self.db.firstkey()
        while key is not None:
            yield key
            key = self.db.nextkey(key)

    def __len__(self):
        return len(self.db)

    def __setitem__(self, path, entry):
        self.db[self.__key_from_path(path)] = entry.as_raw_string()

    def __key_from_path(self, path):
        return os.path.abspath(path)

    def reorganize(self):
        self.db.reorganize()

    def sync(self):
        self.db.sync()

    def update_path(self, path):
        '''Updates the hash for `path` if the file size or modification time
        changed. If no hash for `path` has been stored so far an corresponding
        entry will be created.'''
        exists = path in self
        if exists:
            needs_update = \
                self[path].modification != int(os.path.getmtime(path)) or \
                self[path].size != os.path.getsize(path)
        else:
            needs_update = True
        if needs_update:
            self[path] = HashDb.Entry.from_path(path)

    def update_tree(self, path):
        '''Updates the hash for all files below `path` in the file system tree.
        A hash is updated if the file size or modification time stored in the
        database do not match. A new entry will be created for files if no hash
        has been stored, yet.'''
        def handle_error(err):
            import sys
            msg = [sys.argv[0]]
            if err.strerror is not None:
                if err.filename is not None:
                    msg.append(err.filename)
                msg.append(err.strerror)
            else:
                msg.append("Unknown error.")
            sys.stderr.write(': '.join(msg))
            sys.stderr.write('\n')

        for dirpath, dirnames, filenames in os.walk(path, onerror=handle_error):
            for filename in filenames:
                self.update_path(os.path.join(dirpath, filename))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description="Update database of hashes.")
    parser.add_argument(
        'paths', nargs='*', type=str, help="Paths to update hashes for.")
    parser.add_argument(
        '-d', '--database', nargs=1, type=str, default=['~/.bck-hashes.db'],
        help="Hash database to update.")
    args = parser.parse_args()

    with HashDb(os.path.expanduser(args.database[0])) as db:
        for path in args.paths:
            if os.path.isfile(path):
                db.update_path(path)
            else:
                db.update_tree(path)
