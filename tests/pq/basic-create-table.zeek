# @TEST-DOC: Test that table creation and status querying works
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

global conn: opaque of PQ::Conn;

event create_table()
	{
	when ( local res = PQ::exec(conn, "CREATE TABLE btest (ip inet)" ) )
		{
		local status = PQ::resStatus(res);
		print "create_table", status;
		if ( status == "PGRES_COMMAND_OK" )
			{
			# Try again, expect the failure below.
			event create_table();
			}
		else
			{
			local error_message = PQ::resultErrorMessage(res);
			print "expected error", error_message;
			terminate();
			}
		}
	timeout 1sec
		{
		Reporter::error("timeout");
		exit(1);
		}
	}

event drop_table()
	{
	when ( local res = PQ::exec(conn, "DROP TABLE IF EXISTS btest" ) )
		{
		print "res", PQ::resStatus(res);
		event create_table();
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

	# Run drop, then create
	event drop_table();
	}
