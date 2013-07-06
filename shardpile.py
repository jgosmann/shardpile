#!/usr/bin/env python

import collections
import gdbm
import hashlib
import os
import os.path


def sha1sum(path):
    h = hashlib.sha1()
    with open(path, 'rb') as f:
        buf = '1'
        while buf != '':
            buf = f.read(1024 * 1024)
            h.update(buf)
    return h.hexdigest()


class HashDb(collections.MutableMapping):
    class Entry(object):
        __slots__ = ('modification', 'size', 'sha1')

        def __init__(self, modification, size, sha1):
            self.modification = int(modification)
            self.size = int(size)
            self.sha1 = str(sha1)

        def __eq__(self, other):
            if isinstance(other, self.__class__):
                return self.modification == other.modification and \
                    self.size == other.size and self.sha1 == other.sha1
            return False

        def __ne__(self, other):
            return not self == other

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
            return ';'.join(
                (str(self.modification), str(self.size), self.sha1))

        def __repr__(self):
            return self.as_raw_string()

    def __init__(self, filename, gdbm_module=gdbm):
        self.db = gdbm_module.open(filename, 'cf')

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
        return path

    def reorganize(self):
        self.db.reorganize()

    def sync(self):
        self.db.sync()

    def update_path(self, dirpath, key):
        '''Updates the hash for `path` if the file size or modification time
        changed. If no hash for `path` has been stored so far an corresponding
        entry will be created.'''
        path = os.path.join(dirpath, key)
        exists = key in self
        if exists:
            needs_update = \
                self[key].modification != int(os.path.getmtime(path)) or \
                self[key].size != os.path.getsize(path)
        else:
            needs_update = True
        if needs_update:
            self[key] = HashDb.Entry.from_path(path)

    @staticmethod
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

    def update_tree(self, path):
        '''Updates the hash for all files below `path` in the file system tree.
        A hash is updated if the file size or modification time stored in the
        database do not match. A new entry will be created for files if no hash
        has been stored, yet.'''
        for dirpath, dirnames, filenames in os.walk(
                path, onerror=self.handle_error):
            for filename in filenames:
                try:
                    self.update_path(
                        path,
                        os.path.relpath(os.path.join(dirpath, filename), path))
                except Exception as e:
                    self.handle_error(e)

    def strip(self):
        for key in self.iterkeys():
            if not os.path.exists(key):
                del self[key]

    def verify_tree(self, dirpath):
        changed = []
        missing_in_db = []
        missing_on_disk = []
        for key, value in self.iteritems():
            try:
                path = os.path.join(dirpath, key)
                if not os.path.isfile(path):
                    missing_on_disk.append(key)
                elif value.sha1 != sha1sum(path):
                    changed.append(key)
            except Exception as e:
                self.handle_error(e)
        for path, dirnames, filenames in os.walk(
                dirpath, onerror=self.handle_error):
            for filename in filenames:
                try:
                    relpath = os.path.relpath(
                        os.path.join(path, filename), dirpath)
                    if not relpath in self:
                        missing_in_db.append(relpath)
                except Exception as e:
                    self.handle_error(e)
        return changed, missing_in_db, missing_on_disk


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description="Shardpile maintains a database of SHA1 hashes of a " +
        "tree in the file system and allows to verify trees against this " +
        "hash database.")
    parser.add_argument(
        'paths', nargs='*', type=str, help="Paths to update hashes for.")
    parser.add_argument(
        '-d', '--database', nargs=1, type=str, default=['~/.shardpile.db'],
        help="Hash database to update.")
    parser.add_argument(
        '-u', '--update', action='store_true',
        help="Update the database instead of performing verification.")
    parser.add_argument(
        '--no-strip', action='store_true',
        help="Do not strip hashes of deleted files from the database during " +
        "update.")
    args = parser.parse_args()

    with HashDb(os.path.expanduser(args.database[0])) as db:
        if args.update and not args.no_strip:
            db.strip()

        for path in args.path[0]:
            if args.update:
                if os.path.isfile(path):
                    db.update_path(path)
                else:
                    db.update_tree(path)
            else:
                print(path)
                print(len(path) * '-')
                print('')
                changed, missing_in_db, missing_on_disk = db.verify_tree(path)
                print('Changed:')
                for name in changed:
                    print(name)
                print('')
                print('Missing in DB:')
                for name in missing_in_db:
                    print(name)
                print('')
                print('Missing on disk:')
                for name in missing_on_disk:
                    print(name)
                print('')
                print('')
