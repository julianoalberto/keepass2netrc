from keepass_netrc import KeepassNetrc

if __name__ == "__main__":
    db = KeepassNetrc.open_db('test_keepass_database.kdbx', password='abc123')
    entries = KeepassNetrc.get_netrc_entries(db)
    KeepassNetrc.write_netrc(entries)
