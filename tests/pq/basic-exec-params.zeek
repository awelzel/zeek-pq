# @TEST-DOC: Fetch a single row with dynamic record types.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

global conn: opaque of PQ::Conn;

type MyRow: record {
	ip: addr;
	ip2: addr;
};

event zeek_init()
	{
	# This is blocking, currently...
	conn = PQ::connect("");

	local myip = 192.168.0.1;
	local myip_str = "10.0.0.1";  # string to addr conversion via PQ

	when [myip, myip_str] ( local res = PQ::execParams(conn, "SELECT $1::inet as ip, $2::inet as ip2", myip, myip_str) )
		{
		local rows = PQ::fetchAll(res);
		print "rows", type_name(rows), |rows|, rows;
		local row: MyRow = rows[0];  # dynamic casting
		print "row$ip", row$ip, "row$ip2", row$ip2;
		terminate();
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}
