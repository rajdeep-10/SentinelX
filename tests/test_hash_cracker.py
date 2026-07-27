"""Unit tests for hash_cracker module — no live target needed."""

import sys
import os
import hashlib
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.hash_cracker import HashCracker
import pytest


class TestHashCracker:
    def test_crack_md5_found(self):
        """Test MD5 crack with a known word."""
        # Create a temp wordlist with known content
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
            f.write("password\n")
            f.write("secret\n")
            f.write("hello\n")
            wordlist_path = f.name

        try:
            cracker = HashCracker(wordlist_path=wordlist_path)
            target = hashlib.md5(b"secret").hexdigest()
            result = cracker.crack_md5(target)
            assert result == "secret"
        finally:
            os.unlink(wordlist_path)

    def test_crack_md5_not_found(self):
        """Test MD5 crack returns None when not in wordlist."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
            f.write("alpha\nbeta\n")
            wordlist_path = f.name

        try:
            cracker = HashCracker(wordlist_path=wordlist_path)
            target = hashlib.md5(b"nonexistentpassword").hexdigest()
            result = cracker.crack_md5(target)
            assert result is None
        finally:
            os.unlink(wordlist_path)

    def test_crack_md5_empty_file(self):
        """Test with empty wordlist."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
            wordlist_path = f.name

        try:
            cracker = HashCracker(wordlist_path=wordlist_path)
            target = hashlib.md5(b"anything").hexdigest()
            result = cracker.crack_md5(target)
            assert result is None
        finally:
            os.unlink(wordlist_path)

    def test_crack_md5_with_max_attempts(self):
        """Test that max_attempts limits the search."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
            for i in range(100):
                f.write(f"word{i}\n")
            wordlist_path = f.name

        try:
            cracker = HashCracker(wordlist_path=wordlist_path)
            # word50 should be in the file but at position 50
            target = hashlib.md5(b"word50").hexdigest()
            # With max_attempts=20, we won't reach word50
            result = cracker.crack_md5(target, max_attempts=20)
            assert result is None
            # With max_attempts=100, we should find it
            result = cracker.crack_md5(target, max_attempts=100)
            assert result == "word50"
        finally:
            os.unlink(wordlist_path)

    def test_crack_md5_missing_wordlist(self):
        """Test graceful handling of missing wordlist."""
        cracker = HashCracker(wordlist_path="/tmp/nonexistent_wordlist_xyz123.txt")
        target = hashlib.md5(b"test").hexdigest()
        result = cracker.crack_md5(target)
        assert result is None

    def test_case_insensitive_hash(self):
        """Test that target hash is lowercased before comparison."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="latin-1") as f:
            f.write("testpass\n")
            wordlist_path = f.name

        try:
            cracker = HashCracker(wordlist_path=wordlist_path)
            target = hashlib.md5(b"testpass").hexdigest().upper()
            result = cracker.crack_md5(target)
            assert result == "testpass"
        finally:
            os.unlink(wordlist_path)
