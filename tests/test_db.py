import keepass2netrc
import pykeepass
import pytest

from keepass2netrc import KeepassNetrc
from keepass2netrc import MissingFieldException
from pathlib import Path


DB_PASSWORD = "abc123"
DB_VERSION = (4, 0)
DB_NAME = "test_keepass_database.kdbx"


EXPECTED_LINES = [
    "machine host1.com\tlogin user1\tpassword pass1\n",
    "machine host2.com\tlogin user2\tpassword pass2\n",
    "machine host3.com\tlogin user3\tpassword pass3\n",
]

VALID_TEST_ENTRIES = [
    {
        "title": "ntrc_in_1",
        "username": "user1",
        "password": "pass1",
        "url": "host1.com",
        "tags": ["netrc"],
        "expected_str": "machine host1.com\tlogin user1\tpassword pass1\n",
    },
    {
        "title": "ntrc_in_2",
        "username": "user2",
        "password": "pass2",
        "url": "host2.com",
        "tags": ["netrc"],
        "expected_str": "machine host2.com\tlogin user2\tpassword pass2\n",
    },
    {
        "title": "ntrc_in_3",
        "username": "user3",
        "password": "pass3",
        "url": "host3.com",
        "tags": ["netrc"],
        "expected_str": "machine host3.com\tlogin user3\tpassword pass3\n",
    },
    {
        "title": "ntrc_out_1",
        "username": "user1",
        "password": "pass1",
        "url": "host1.com",
        "tags": ["netrc", "no_netrc"],
        "expected_str": "machine host1.com\tlogin user1\tpassword pass1\n",
    },
    {
        "title": "ntrc_out_2",
        "username": "user2",
        "password": "pass2",
        "url": "host2.com",
        "tags": ["tag1", "tag2"],
        "expected_str": "machine host2.com\tlogin user2\tpassword pass2\n",
    },
    {
        "title": "ntrc_out_3",
        "username": "user3",
        "password": "pass3",
        "url": "host3.com",
        "tags": [],
        "expected_str": "machine host3.com\tlogin user3\tpassword pass3\n",
    },
]

EXPECTED_NETRC_ENTRIES = [
    {
        "title": "ntrc_in_1",
        "username": "user1",
        "password": "pass1",
        "url": "host1.com",
        "tags": ["netrc"],
    },
    {
        "title": "ntrc_in_2",
        "username": "user2",
        "password": "pass2",
        "url": "host2.com",
        "tags": ["netrc"],
    },
    {
        "title": "ntrc_in_3",
        "username": "user3",
        "password": "pass3",
        "url": "host3.com",
        "tags": ["netrc"],
    },
]

INVALID_TEST_ENTRIES = [
    {
        "title": "no_user",
        "username": "",
        "password": "pass1",
        "url": "host3.com",
        "tags": ["netrc"],
        "missing_fields": ["username"],
    },
    {
        "title": "no_password",
        "username": "invalid_no_password_user",
        "password": "",
        "url": "host3.com",
        "tags": ["netrc"],
        "missing_fields": ["password"],
    },
    {
        "title": "no_url",
        "username": "invalid_no_url_user",
        "password": "pass1",
        "url": "",
        "tags": ["netrc"],
        "missing_fields": ["url"],
    },
    {
        "title": "no_all",
        "username": "",
        "password": "",
        "url": "",
        "tags": ["netrc"],
        "missing_fields": ["url", "username", "password"],
    },
]


def create_test_db(path, entries):
    db = pykeepass.create_database(str(path / DB_NAME), password=DB_PASSWORD)

    for entry in entries:
        db.add_entry(
            db.root_group,
            title=entry["title"],
            username=entry["username"],
            password=entry["password"],
            url=entry["url"],
            tags=entry["tags"],
        )
    return db


def test_get_netrc_entry_str_valid(tmp_path):
    db = create_test_db(path=tmp_path, entries=VALID_TEST_ENTRIES)
    keepass_netrc = KeepassNetrc(tmp_path / DB_NAME, DB_PASSWORD)

    for test_entry in VALID_TEST_ENTRIES:
        entry = pykeepass.entry.Entry(
            title=test_entry["title"],
            username=test_entry["username"],
            password=test_entry["password"],
            url=test_entry["url"],
            kp=db,
        )
        assert keepass_netrc.get_netrc_entry_str(entry) == test_entry["expected_str"]


def test_get_netrc_entry_str_invalid(tmp_path):
    db = create_test_db(path=tmp_path, entries=INVALID_TEST_ENTRIES)
    keepass_netrc = KeepassNetrc(tmp_path / DB_NAME, DB_PASSWORD)

    for test_entry in INVALID_TEST_ENTRIES:
        entry = pykeepass.entry.Entry(
            title=test_entry["title"],
            username=test_entry["username"],
            password=test_entry["password"],
            url=test_entry["url"],
            kp=db,
        )

        with pytest.raises(MissingFieldException) as exc:
            keepass_netrc.get_netrc_entry_str(entry)

        assert exc.value.args[1] == test_entry["missing_fields"]


def test_get_netrc_entries(tmp_path):
    db = create_test_db(path=tmp_path, entries=VALID_TEST_ENTRIES)
    keepass_netrc = KeepassNetrc(tmp_path / DB_NAME, DB_PASSWORD)
