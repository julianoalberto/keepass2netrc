import logging
import pathlib
import pykeepass
import typing


DEFAULT_TAGS = ["netrc"]

NETRC_ENTRY_TEMPLATE = "machine {}\tlogin {}\tpassword {}\n"


class MissingFieldException(Exception):
    """
    Raised when one or more of the fields are missing
    """


class KeepassNetrc:
    def __init__(self, db_path: pathlib.Path, password: str):
        self.db_path = db_path
        self.password = password
        self.db = self.open_db()

    def open_db(self) -> pykeepass.PyKeePass:
        """
        Open the given KeePass database using the given password.

        :param pathlib.Path db_path: path to the KeePass database
        :param str password: password of the KeePass database
        :return pykeepass.PyKeePass: an open KeePass database
        """
        logging.debug("Openning database: %s", self.db_path)
        return pykeepass.PyKeePass(self.db_path, self.password)

    def get_netrc_entry_str(self, entry: pykeepass.entry.Entry) -> str:
        missing_fields: typing.List[str] = []

        if not entry.url:
            missing_fields.append("url")
        if not entry.username:
            missing_fields.append("username")
        if not entry.password:
            missing_fields.append("password")

        if missing_fields:
            raise MissingFieldException(
                "Entry  missing field(s)", missing_fields
            )

        return NETRC_ENTRY_TEMPLATE.format(
            entry.url, entry.username, entry.password
        )

    def _validate_entry(self, entry: pykeepass.entry.Entry):
        missing_fields: typing.List[str] = []

        if not entry.url:
            missing_fields.append("url")
        if not entry.username:
            missing_fields.append("username")
        if not entry.password:
            missing_fields.append("password")

        if missing_fields:
            raise MissingFieldException(
                "Invalid entry", "Missing field(s)", missing_fields
            )

    def get_netrc_entries(
        self, tags: typing.List[str] = DEFAULT_TAGS
    ) -> typing.List[pykeepass.entry.Entry]:
        """
        Get all entries from the given KeePass database that contain the given
        list of tags.

        :param pykeepass.PyKeePass db: KeePass database with the entries
        :param list[str] tags: list of tags to be matched, defaults to ["netrc"]
        :return list[pykeepass.entry.Entry]: list of entries that contain the exact
            same tags as in the passed tags list
        """
        netrc_entries = []
        tags_set = set(tags)

        logging.debug("self.db.entries: %s", self.db.entries)
        for entry in self.db.entries:
            logging.debug("entry: %s, entry.tags: %s", entry, entry.tags)

            # pykeepass.entry.Entry.tags holds a list with a single string
            # separated by commas, like ['tag1,tag2'], instead of a list with
            # one string per tag, like ['tag1', 'tag2'].
            #
            # So it is necessary to convert it with:
            #   set(entry.tags[0].split(",")
            entry_tags_list = entry.tags[0].split(",")
            if entry.tags and tags_set == set(entry_tags_list):
                try:
                    logging.warning("entry.tags     : %s", entry.tags)
                    logging.warning("entry_tags_list: %s", entry_tags_list)
                    self._validate_entry(entry)
                    netrc_entries.append(entry)
                    logging.debug("included entry: %s", entry)
                except MissingFieldException as exc:
                    logging.warning(
                        "entry not included: %s / missing fields: %s",
                        entry,
                        exc.args[2],
                    )
        logging.debug("included netrc entries: %s", netrc_entries)
        netrc_entries = sorted(netrc_entries, key=lambda e: e.url)

        logging.debug("included netrc entries: %s", netrc_entries)

        return netrc_entries

    def write_netrc(
        self,
        netrc_file: pathlib.Path,
        tags: typing.List[str] = DEFAULT_TAGS,
        backup: bool = True,
    ) -> None:
        if netrc_file.exists():
            logging.warning("netrc_file exists: %s", netrc_file)

        with open(netrc_file, "w") as netrc:
            for entry in self.get_netrc_entries(tags):
                netrc.write(self.get_netrc_entry_str(entry))
