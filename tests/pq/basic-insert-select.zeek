# @TEST-DOC: Create a table and insert 5 rows, then select them back.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

global conn: opaque of PQ::Conn;


event select()
	{
	when ( local res = PQ::execParams(conn, "SELECT * FROM btest ORDER BY id ASC" ) )
		{
		local status = PQ::resStatus(res);
		local ntuples = PQ::ntuples(res);
		local cmdtuples = PQ::cmdTuples(res);
		local rows = PQ::fetchAll(res);
		print "select", status, ntuples, cmdtuples, |rows|;

		for ( i in rows )
			print type_name(rows[i]), rows[i];

		terminate();
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}


event insert(c: count)
	{
	local ip = count_to_v4_addr(addr_to_counts(192.168.0.1)[0] + c);

	when [c, ip] ( local res = PQ::execParams(conn, "INSERT INTO btest VALUES ($1, $2)", c, ip ) )
		{
		local status = PQ::resStatus(res);
		print "insert status", status;
		if ( status != "PGRES_COMMAND_OK" )
			exit(1);

		if (c == 0)
			event select();
		else
			event insert(--c);
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}


event setup()
	{
	when ( local res1 = PQ::exec(conn, "DROP TABLE IF EXISTS btest" ) )
		{
		when ( local res2 = PQ::exec(conn, "CREATE TABLE btest (id int, ip inet)" ) )
			{
			local status = PQ::resStatus(res2);
			print "create_table", status;
			if ( status == "PGRES_COMMAND_OK" )
				event insert(5);
			else
				exit(1);
			}
		timeout 1sec
			{
			Reporter::error("timeout");
			exit(1);
			}
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}

event zeek_init()
	{
	# This is blocking, currently...
	conn = PQ::connect("");

	event setup();
	}
