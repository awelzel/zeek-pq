import argparse
import contextlib
import ipaddress
import re
import time

import postgresql
import postgresql.versionstring

# monkey patch postgresql.versionstring.split to accept 14.5 (Debian 14.5-1.pgdg110+1)
# https://github.com/python-postgres/fe/issues/109

_orig_split = postgresql.versionstring.split


def _monkey_split(vstr):
    m = re.match("^([0-9]+\.[0-9]+[^\s]*)\s+\(.+\)$", vstr)
    if m is not None:
        vstr = m.group(1)
    return _orig_split(vstr)


postgresql.versionstring.split = _monkey_split


@contextlib.contextmanager
def timeit(*args, **kwargs):
    start_time = time.time()
    try:
        yield
    finally:
        end_time = time.time()
        print(f"{args}, {kwargs} {((end_time - start_time) * 1000):.3f} msec")


class Query:
    def __init__(self, conn):
        self.conn = conn

    @timeit()
    def lookup_ip(self, ip):
        # ipx = ipaddress.ip_address(ip)
        # row = self.conn.query("SELECT * FROM intel_ip WHERE ip = $1", ipx)
        # Meeh, py-postgresql does not support the inet type natively it
        # appears, so cast around. psycopg2 does support it properly.
        #
        # TIL: Do not use py-postgresql
        return self.conn.query("SELECT * FROM intel_ip WHERE ip = ($1::text)::inet", ip)


def rebuild_table(conn, count):
    """
    Build an intel_ip table with count IP address entries.
    """
    conn.execute(
        """
        DROP TABLE IF EXISTS intel_ip;
    """
    )

    # This is a naive table layout. The source information may or may
    # not be held in a separate table.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS intel_ip (
            ip inet,
            source text,
            description text,
            url text);
    """
    )

    insert_stmt = conn.prepare(
        "INSERT INTO intel_ip VALUES (($1::text)::inet, $2, $3, $4)"
    )

    # There's load_rows() which is probably much much faster.
    start_ip = 100000000
    for i in range(count):
        i += 1

        ip = ipaddress.ip_address(start_ip + i)
        source = "source1-" + str(i)
        description = "Generated IP - " + str(ip)
        url = "http://localhost/intel/q=" + str(ip)

        insert_stmt(str(ip), source, description, url)

    # print("building gist index")
    # conn.execute("""
    #    CREATE INDEX idx_intel_ip_gist ON intel_ip USING gist (ip inet_ops);
    # """)

    # Very little testing indicates the hash index is faster. For 1mio
    # entries it requires 32MB of space, while the gist takes up 30MB.
    # We don't care about 2MB for 2mio entries.
    print("building hash index")
    conn.execute(
        """
        CREATE INDEX idx_intel_ip_hash ON intel_ip USING hash(ip);
    """
    )

    print("vacuum analyze")
    conn.execute(
        """
        VACUUM ANALYZE intel_ip;
    """
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iri", default="pq://zeek@127.0.0.1/zeek")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--rebuild-table", action="store_true")
    args = parser.parse_args()

    conn = postgresql.open(args.iri)

    if args.rebuild_table:
        if args.count == 0:
            raise parser.error("Use --count, please")
        rebuild_table(conn, args.count)

    else:
        q = Query(conn)
        __import__("IPython").embed(banner1="")


if __name__ == "__main__":
    main()
