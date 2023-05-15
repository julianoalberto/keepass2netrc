import argparse
import datetime
import getpass
import logging
import os
import pathlib
import keepass2netrc

DEFAULT_DB_PASS_ENV_VAR_NAME = "KEEPASS_DB_PASS"

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("keepass_netrc_cli")


def get_args():
    parser = argparse.ArgumentParser(
        description="Export KeePass database to netrc",
        epilog=(
            """
            This tool reads a KeePass database and exports its entries in
            netrc format.
            """
        ),
    )

    parser.add_argument(
        "--database-path",
        type=pathlib.Path,
        required=True,
        dest="dbpath",
        help="Path to KeePass database.",
    )

    parser.add_argument(
        "--netrc-output-file",
        type=pathlib.Path,
        required=False,
        default=pathlib.Path(pathlib.Path.home() / ".netrc"),
        dest="outnetrc",
        help="Output netrc file. Default: $HOME/.netrc",
    )

    parser.add_argument(
        "--netrc-tags",
        type=str,
        nargs="*",
        required=False,
        default=keepass2netrc.DEFAULT_TAGS,
        action="store",
        dest="tags",
        help=f"""Only entries with ALL these tags will be included in the
                 generated netrc file. Default: {', '.join(keepass2netrc.DEFAULT_TAGS)}""",
    )

    parser.add_argument(
        "--database-pass-env-var",
        dest="dbpassvar",
        required=False,
        default=DEFAULT_DB_PASS_ENV_VAR_NAME,
        help=f"""Name of the environment variable that holds the KeePass database password.
                Default: {DEFAULT_DB_PASS_ENV_VAR_NAME}""",
    )

    parser.add_argument(
        "--ask-database-pass",
        default=False,
        action="store_true",
        dest="askpass",
        help="Whether or not to prompt for KeePass database password.",
    )

    return parser.parse_args()


def backup(original_netrc: pathlib.Path) -> None:
    if original_netrc.is_file():
        now = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

        backup_netrc = pathlib.Path(
            original_netrc.parent / (original_netrc.name + f"~{now}")
        )
        logging.info("%s backed up to %s", original_netrc, backup_netrc)
        original_netrc.rename(backup_netrc)
    else:
        logging.debug("%s does not exist", original_netrc)


def run():
    args = get_args()
    logging.debug(args)

    dbpass = os.getenv(args.dbpassvar)
    if not dbpass:
        if args.askpass:
            logging.debug("prompting for database password")
            print(f"KeePass database: {args.dbpath}")
            dbpass = getpass.getpass()
        else:
            logging.debug("password not provided")
            exit(code=1)

    db: keepass2netrc.KeepassNetrc = keepass2netrc.KeepassNetrc(
        db_path=args.dbpath, password=dbpass
    )
    backup(args.outnetrc)
    db.write_netrc(args.outnetrc, args.tags)
