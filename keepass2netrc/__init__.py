import pathlib
import pykeepass
import typing

from jinja2 import Template


DEFAULT_TAGS = ["netrc"]

NETRC_ENTRY_TEMPLATE = "machine {}\tlogin {}\tpassword {}\n"
INVALID_NETRC_ENTRY_TEMPLATE = "# machine {}\tlogin {}\tpassword {}\n"


class MissingFieldException(Exception):
    """
    Raised when one or more of the fields are missing
    """


class KeepassNetrc:
    def __init__(self, db_path: pathlib.Path, password: str):
        self.db_path = db_path
        self.password = password
        self.db = pykeepass.PyKeePass(db_path, password)

    # def open_db(db_path: pathlib.Path, password: str) -> pykeepass.PyKeePass:
    #     """
    #     Open the given KeePass database using the given password.

    #     :param pathlib.Path db_path: path to the KeePass database
    #     :param str password: password of the KeePass database
    #     :return pykeepass.PyKeePass: an open KeePass database
    #     """
    #     return pykeepass.PyKeePass(db_path, password)

    def get_netrc_entry_str(self, entry: pykeepass.entry.Entry) -> str:
        missing_fields: typing.List[str] = []

        if not entry.url:
            missing_fields.append("url")
        if not entry.username:
            missing_fields.append("username")
        if not entry.password:
            missing_fields.append("password")

        if missing_fields:
            raise MissingFieldException("Entry  missing field(s)", missing_fields)

        return NETRC_ENTRY_TEMPLATE.format(entry.url, entry.username, entry.password)

    def get_netrc_entries(
        db: pykeepass.PyKeePass, tags: typing.List[str] = DEFAULT_TAGS
    ) -> typing.List[pykeepass.entry.Entry]:
        """
        Get all entries from the given KeePass database that contain the given
        list of tags.

        :param pykeepass.PyKeePass db: KeePass database with the entries
        :param list[str] tags: list of tags to be matched, defaults to ["netrc"]
        :return list[pykeepass.entry.Entry]: list of entries that contain the exact
            same tags as in the passed tags list
        """
        for entry in db.entries:
            if entry.tags and (set(tags) == set(entry.tags)):
                print(entry)

            # return sorted(entries, key=lambda e: e.url)

    def write_netrc(entries: typing.List[pykeepass.entry.Entry]) -> None:
        print(entries)

        with open("netrc", "w") as netrc:
            for entry in entries:
                netrc.write(
                    NETRC_ENTRY_TEMPLATE.format(
                        entry.url, entry.username, entry.password
                    )
                )
