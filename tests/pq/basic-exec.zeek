# @TEST-DOC: Fetch a single row. Use dynamic record type construction.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

type MyRow: record {
	ip: addr;
};

global conn: opaque of PQ::Conn;

event zeek_init()
	{
	# This is blocking, currently...
	conn = PQ::connect("");

	when ( local res = PQ::exec(conn, "SELECT '192.168.0.1'::inet as ip, 'Hello!'::text as text") )
		{
		local rows = PQ::fetchAll(res);
		print "rows", type_name(rows), |rows|, rows;
		local row: MyRow = rows[0];  # dynamic casting
		print "row$ip", row$ip;
		terminate();
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}
