#!/usr/bin/env python

import __builtin__
import gdbm
import errno
import hashlib
import os
import os.path
import unittest
import sys
from mock import call, MagicMock, mock_open, patch
from StringIO import StringIO
from shardpile import HashDb


class FilesMock(object):
    class File(object):
        content = 'content'

        def __init__(self, mtime, size):
            self.mtime = mtime
            self.size = size

    def __init__(self):
        self.files = {}
        self.path = patch('os.path')
        self.open = patch('__builtin__.open', mock_open(), create=True)

    def __enter__(self):
        self.open.start()
        __builtin__.open = MagicMock(side_effect=self.mock_file)
        self.path.start()
        os.path.getmtime = MagicMock(side_effect=self.getmtime)
        os.path.getsize = MagicMock(side_effect=self.getsize)
        os.path.isfile = MagicMock(side_effect=self.isfile)
        os.path.join = MagicMock(side_effect=self.join)
        return self

    def __exit__(self, type, value, traceback):
        self.path.stop()
        self.open.stop()

    def add_file(self, path, mtime, size):
        self.files[path] = self.File(mtime, size)

    def mock_file(self, filename, mode):
        def read(size):
            file_mock.read.side_effect = lambda size: ''
            return self.File.content

        file_mock = MagicMock()
        file_mock.__enter__.return_value = file_mock
        file_mock.read.side_effect = read
        return file_mock

    def getmtime(self, path):
        try:
            return self.files[path].mtime
        except KeyError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)

    def getsize(self, path):
        try:
            return self.files[path].size
        except KeyError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)

    def isfile(self, path):
        return path in self.files

    def join(self, *args):
        return '/'.join(args)


class HashDbTest(unittest.TestCase):
    def setUp(self):
        self.data = {
            '/path/to/somefile':
            '1366207797;1024;6cf9224c0ced0affde6832a101676ff656a7cd6f',
            '/path/to/anotherfile':
            '1366207797;1024;040f06fd774092478d450774f5ba30c5da78acc8'
        }

        def data_delitem(key):
            del self.data[key]

        def data_getitem(key):
            return self.data[key]

        def data_setitem(key, value):
            self.data[key] = value

        def data_nextkey(key):
            key_iter = iter(self.data)
            while key_iter.next() != key:
                pass
            return key_iter.next()

        self.dbmock = MagicMock()
        self.dbmock.__delitem__.side_effect = data_delitem
        self.dbmock.__getitem__.side_effect = data_getitem
        self.dbmock.__setitem__.side_effect = data_setitem
        self.dbmock.__len__.side_effect = lambda: len(self.data)
        self.dbmock.firstkey.side_effect = lambda: self.data.iterkeys().next()
        self.dbmock.nextkey.side_effect = data_nextkey

        self.gdbm_mock = MagicMock(spec_set=gdbm)
        self.gdbm_mock.open.return_value = self.dbmock
        self.hashdb = HashDb('<filename>', self.gdbm_mock)

    def test_can_be_used_in_with(self):
        with FilesMock() as files:
            files.add_file('/path/to/somefile', 1366207797, 1024)
            with HashDb('<filename>', self.gdbm_mock) as db:
                db.update_path('/path/to/somefile')

    def test_allows_iteration(self):
        keys = ['0', '1', '2', None]
        self.dbmock.firstkey.side_effect = lambda: keys[0]
        self.dbmock.nextkey.side_effect = lambda key: keys[keys.index(key) + 1]

        for key in self.hashdb:
            self.assertTrue(key in keys, 'key = %s' % key)

    def test_has_length(self):
        self.assertEqual(len(self.hashdb), len(self.data))

    def test_provides_dictionary_interface(self):
        entry = self.hashdb['/path/to/somefile']
        self.assertEqual(entry.modification, 1366207797)
        self.assertEqual(entry.size, 1024)
        self.assertEqual(entry.sha1, '6cf9224c0ced0affde6832a101676ff656a7cd6f')

        with self.assertRaises(KeyError):
            entry = self.hashdb['/newpath']

        self.hashdb['/newpath'] = HashDb.Entry(
            12345, 256, '07d307d64e062a0ba2ed725571aecd89f2214232')
        self.assertEqual(
            self.data['/newpath'],
            '12345;256;07d307d64e062a0ba2ed725571aecd89f2214232')

    def test_uses_relative_paths(self):
        entry = HashDb.Entry(
            1, 2, '07d307d64e062a0ba2ed725571aecd89f2214232')
        self.hashdb['name'] = entry
        self.assertIn('name', self.data)
        self.assertEqual(self.hashdb['name'], entry)
        self.assertNotIn('/cwd/name', self.data)

    def test_allows_deletion_of_entries(self):
        del self.hashdb['/path/to/somefile']
        self.assertFalse('/path/to/somefile' in self.hashdb)

    def test_inserts_hash_for_new_file(self):
        with FilesMock() as files:
            files.add_file('/newfile', 123, 42)
            self.hashdb.update_path('/newfile')

        expected = HashDb.Entry(
            123, 42, hashlib.sha1(FilesMock.File.content).hexdigest())
        self.assertEqual(self.hashdb['/newfile'], expected)

    def test_reads_complete_file(self):
        with FilesMock() as files:
            with patch('__builtin__.open', mock_open()) as open_patch:
                chunks = ['con', 'tent', '']

                def read_chunk(size):
                    return chunks.pop(0)

                file_mock = MagicMock()
                file_mock.__enter__.return_value = file_mock
                file_mock.read.side_effect = read_chunk
                open_patch.return_value = file_mock

                files.add_file('/newfile', 123, 42)
                self.hashdb.update_path('/newfile')

        expected = HashDb.Entry(
            123, 42, hashlib.sha1('content').hexdigest())
        self.assertEqual(self.hashdb['/newfile'], expected)

    def test_updates_hash_if_modification_time_changed(self):
        with FilesMock() as files:
            files.add_file('/path/to/somefile', 123, 1024)
            self.hashdb.update_path('/path/to/somefile')

        expected = HashDb.Entry(
            123, 1024, hashlib.sha1(FilesMock.File.content).hexdigest())
        self.assertEqual(self.hashdb['/path/to/somefile'], expected)

    def test_updates_hash_if_size_changed(self):
        with FilesMock() as files:
            files.add_file('/path/to/somefile', 1366207797, 42)
            self.hashdb.update_path('/path/to/somefile')

        expected = HashDb.Entry(
            1366207797, 42, hashlib.sha1(FilesMock.File.content).hexdigest())
        self.assertEqual(self.hashdb['/path/to/somefile'], expected)

    def test_does_not_update_hash_if_modification_and_size_unchanged(self):
        with FilesMock() as files:
            files.add_file('/path/to/somefile', 1366207797, 1024)
            self.hashdb.update_path('/path/to/somefile')

        expected = HashDb.Entry(
            1366207797, 1024, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        self.assertEqual(self.hashdb['/path/to/somefile'], expected)

    def test_update_path_throws_exception_for_non_existing_files(self):
        with FilesMock() as files:
            files.add_file('/existent', 1, 1)
            with self.assertRaises(OSError) as cm:
                self.hashdb.update_path('/nonexistent')

        self.assertEqual(cm.exception.errno, errno.ENOENT)

    def test_can_update_all_paths_in_tree(self):
        with patch('os.walk') as walk:
            dirpath = '/dir'
            walk.return_value = [
                (dirpath, ['a', 'b'], ['file0', 'file1']),
                (os.path.join(dirpath, 'a'), [], ['file2']),
                (os.path.join(dirpath, 'b'), [], ['file3', 'file4'])]
            with patch.object(self.hashdb, 'update_path') as update_path:
                self.hashdb.update_tree(dirpath)

                expected = [call(os.path.join(dirpath, f)) for f in [
                    'file0', 'file1', os.path.join('a', 'file2'),
                    os.path.join('b', 'file3'), os.path.join('b', 'file4')]]
                self.assertEqual(
                    len(update_path.call_args_list), len(expected))
                for c in update_path.call_args_list:
                    self.assertIn(c, expected)

    def test_update_all_prints_walk_errors_and_continues(self):
        with patch('os.walk') as walk:
            dirpath = '/dir'

            def test_error_handler(path, onerror):
                with patch('sys.stderr') as stderr:
                    buffer = StringIO()
                    stderr.write = buffer.write
                    onerror(OSError(
                        errno.EPERM, 'Permission denied.', 'somedir'))
                    self.assertEqual(
                        buffer.getvalue(),
                        sys.argv[0] + ": somedir: Permission denied.\n")
                return [(dirpath, [], [])]

            walk.side_effect = test_error_handler
            self.hashdb.update_tree(dirpath)

    def test_update_all_prints_update_path_errors_and_continues(self):
        with patch('os.walk') as walk:
            dirpath = '/dir'
            walk.return_value = [(dirpath, [], ['file'])]
            with patch('sys.stderr') as stderr:
                buffer = StringIO()
                stderr.write = buffer.write
                with patch.object(self.hashdb, 'update_path') as update_path:
                    update_path.side_effect = OSError(
                        errno.EPERM, 'Permission denied.', 'file')
                    self.hashdb.update_tree(dirpath)

                self.assertEqual(
                    buffer.getvalue(),
                    sys.argv[0] + ": file: Permission denied.\n")

    def test_verify_tree(self):
        self.data['/path/missingOnDisk'] = \
            '1366207797;1024;040f06fd774092478d450774f5ba30c5da78acc8'
        with patch('os.walk') as walk:
            dirpath = '/path'
            walk.return_value = [
                (dirpath, ['to'], ['missingInDb']),
                (os.path.join(dirpath, 'to'), [], ['somefile']),
                (os.path.join(dirpath, 'to'), [], ['anotherfile'])]
            with FilesMock() as files:
                files.add_file('/path/to/somefile', 1, 1)
                files.add_file('/path/to/anotherfile', 1, 1)
                changed, missing_in_db, missing_on_disk = \
                    self.hashdb.verify_tree(dirpath)
        self.assertEqual(changed, ['/path/to/somefile'])
        self.assertEqual(missing_in_db, ['/path/missingInDb'])
        self.assertEqual(missing_on_disk, ['/path/missingOnDisk'])

    # TODO: Test for error handling


class HashDbEntryTest(unittest.TestCase):
    def test_equal_entries_considered_equal(self):
        a = HashDb.Entry(123, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        b = HashDb.Entry(123, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        self.assertEqual(a, b)

    def test_entries_differing_in_modification_time_are_unequal(self):
        a = HashDb.Entry(123, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        b = HashDb.Entry(23, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        self.assertNotEqual(a, b)

    def test_entries_differing_in_size_are_unequal(self):
        a = HashDb.Entry(123, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        b = HashDb.Entry(123, 23, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        self.assertNotEqual(a, b)

    def test_entries_differing_in_sha1_are_unequal(self):
        a = HashDb.Entry(123, 456, '6cf9224c0ced0affde6832a101676ff656a7cd6f')
        b = HashDb.Entry(123, 456, '07d307d64e062a0ba2ed725571aecd89f2214232')
        self.assertNotEqual(a, b)


if __name__ == '__main__':
    unittest.main()
