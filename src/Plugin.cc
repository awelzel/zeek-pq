#include "Plugin.h"

#include <zeek/DebugLogger.h>
#include <zeek/IPAddr.h>
#include <zeek/Trigger.h>
#include <zeek/ZeekString.h>
#include <zeek/iosource/Manager.h>
#include <cstdio>
#include <iomanip> // std::get_time

extern "C"
	{
#undef HAVE_GETOPT_H
#undef HAVE_GETOPT_LONG
#undef HAVE_MEMORY_H
// Need to be this way around!
// clang-format off
#include <postgres.h>
#include <catalog/pg_type.h>
	}
// clang-format on

// Postgres headers doing things to it.
#undef snprintf

namespace plugin
	{
namespace Zeek_PQ
	{
Plugin plugin;
	}
	}

using namespace plugin::Zeek_PQ;

namespace
	{
zeek::OpaqueTypePtr opaque_of_pq_conn;
zeek::OpaqueTypePtr opaque_of_pq_result;

void emit_builtin_error_pq(PGconn* pg_conn, const char* msg)
	{
	zeek::reporter->Error("%s: %s (%s)", plugin::Zeek_PQ::plugin.Name().c_str(), msg,
	                      PQerrorMessage(pg_conn));
	}

zeek::ValPtr val_for(zeek::TypeTag tag, char* v, int length)
	{
	switch ( tag )
		{
		case zeek::TYPE_STRING:
			return zeek::make_intrusive<zeek::StringVal>(length, v);
		case zeek::TYPE_DOUBLE:
			return zeek::make_intrusive<zeek::DoubleVal>(atof(v));
		case zeek::TYPE_ADDR:
			return zeek::make_intrusive<zeek::AddrVal>(v);
		case zeek::TYPE_SUBNET:
			{
			// XXX: Is IPv6 working right?
			return zeek::make_intrusive<zeek::SubNetVal>(v);
			}
		case zeek::TYPE_TIME:
			{
			// Grumble, grumble this is for now() returning a timezone.
			// 2022-09-17 22:32:13.526461+00
			std::string data{v, static_cast<unsigned long>(length)};
			int idx_dot = data.find('.');
			int idx_plus = data.find('+', idx_dot);
			int idx_min = data.find('-', idx_dot);
			int micros_end = std::max(idx_min, idx_plus);

			// Ensure there was a + or - for the timezone
			if ( micros_end < idx_dot )
				{
				zeek::reporter->Error("Bad timestamp: %s", data.c_str());
				return zeek::make_intrusive<zeek::TimeVal>(0.0);
				}

			std::string micros_str = data.substr(idx_dot + 1, micros_end - idx_dot - 1);
			int micros = atoi(micros_str.c_str());

			std::string get_time_data = data.substr(0, idx_dot) + data.substr(micros_end);

			struct tm tm = {0};
			char* sret = strptime(get_time_data.c_str(), "%Y-%m-%d %H:%M:%S%z", &tm);

			long int offset = tm.tm_gmtoff;
			double ts = static_cast<double>(timegm(&tm));
			ts = (ts - offset) + micros / (1000.0 * 1000.0);

			return zeek::make_intrusive<zeek::TimeVal>(ts);
			}
		default:
			PLUGIN_DBG_LOG(plugin::Zeek_PQ::plugin, "XXX Unhandled TypeTag %d", tag);
			zeek::reporter->Error("XXX Unhandled TypeTag %d", tag);
			return zeek::Val::nil;
		}
	}

zeek::TypeDecl* type_decl_for(const char* name, Oid pg_type)
	{
	zeek::TypeTag zeek_tag;
	switch ( pg_type )
		{
		case TIMESTAMPTZOID:
			zeek_tag = zeek::TYPE_TIME;
			break;
		case INETOID:
			zeek_tag = zeek::TYPE_ADDR;
			break;
		case CIDROID:
			zeek_tag = zeek::TYPE_SUBNET;
			break;
		case TEXTOID:
			zeek_tag = zeek::TYPE_STRING;
			break;
		case NUMERICOID:
			zeek_tag = zeek::TYPE_DOUBLE;
			break;
		default:
			PLUGIN_DBG_LOG(plugin::Zeek_PQ::plugin,
			               "XXX Unhandled type oid %d - defaulting to string", pg_type);
			zeek_tag = zeek::TYPE_STRING;
		}

	zeek::TypePtr type_ptr = zeek::base_type(zeek_tag);
	return new zeek::TypeDecl(zeek::util::copy_string(name), type_ptr);
	}
	}

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::PQ";
	config.description = "Low-level PostgreSQL access";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}

void Plugin::InitPostScript()
	{
	PLUGIN_DBG_LOG(plugin, "InitPreScript %s", "PQ::Conn");
	opaque_of_pq_conn = zeek::make_intrusive<zeek::OpaqueType>("PQ::Conn");
	opaque_of_pq_result = zeek::make_intrusive<zeek::OpaqueType>("PQ::Result");
	}

PQConn::PQConn(PGconn* pg_conn) : OpaqueVal(opaque_of_pq_conn), pg_conn(pg_conn, PQfinish) { 
	PLUGIN_DBG_LOG(plugin, "Registering %s",  Tag());
	int fd = PQsocket(pg_conn);
	zeek::iosource_mgr->RegisterFd(fd, this);


}
PQConn::~PQConn()
	{
	PLUGIN_DBG_LOG(plugin, "Unregistering %s",  Tag());
	int fd = PQsocket(pg_conn.get());
	zeek::iosource_mgr->UnregisterFd(fd, this);
	}

const char* PQConn::Tag()
	{
	return zeek::util::fmt("PQConn-%d", PQbackendPID(pg_conn.get()));
	}

double PQConn::GetNextTimeout()
	{
	return -1.0;
	}

void PQConn::Process()
	{
	PQconsumeInput(pg_conn.get());

	if ( PQisBusy(pg_conn.get()) )
		return;

	PLUGIN_DBG_LOG(plugin, "Process(): Connection ready!");

	PGresult* pg_result = PQgetResult(pg_conn.get());
	if ( ! pg_result )
		{
		emit_builtin_error_pq(pg_conn.get(), "Error with PQgetResult()");
		return;
		}

	auto pq_result = new PQResult(pg_result);

	ExecStatusType status = PQresultStatus(pg_result);
	char* status_str = PQresStatus(status);
	char* error_str = PQresultErrorMessage(pg_result);
	PLUGIN_DBG_LOG(plugin, "result status=%s error=%s", status_str, error_str);

	// We need to call PQgetResult to clear the command status and expect
	// it to return null now, print an error for any non-null results we see.
	//
	// For pipelining support, this would need to change.
	while ( pg_result = PQgetResult(pg_conn.get()), pg_result )
		{
		zeek::reporter->Error("Unexpected non-null PQgetResult() response");
		PQclear(pg_result);
		}

	trigger->Cache(trigger_assoc, pq_result);
	Unref(pq_result); // The when/trigger owns the reuslt.
	trigger->Release();

	trigger = nullptr;
	trigger_assoc = nullptr;

	}

int PQConn::SendQuery(const char* command)
	{
	int r = PQsendQuery(pg_conn.get(), command);
	if ( r != 1 )
		emit_builtin_error_pq(pg_conn.get(), "Error with PQsendQuery()");
	return r;
	}

int PQConn::SendQueryParams(const char* command, zeek::ValPList& args)
	{
	const Oid* param_types = nullptr;
	std::vector<const char*> param_values{args.size(), nullptr};

	// Dynamically allocated storage for stringified parameters
	constexpr int scratch_size = 32;
	std::vector<std::vector<char>> scratch_buffers;

	const int* param_lengths = nullptr;  // ignored, text only
	const int* param_formats = nullptr;  // ignored, text only
	int result_format = 0; // text format

	int i = 0;
	for ( auto a : args )
		{
		auto& t = a->GetType();
		PLUGIN_DBG_LOG(plugin, "SendQueryParams arg[%d] %p %d", i, a, t->Tag());

		switch ( t->Tag() )
			{
			case zeek::TYPE_ADDR:
				{
				param_values[i] = a->AsAddr().AsString().c_str();
				break;
				}
			case zeek::TYPE_COUNT:
				{
				auto& buf = scratch_buffers.emplace_back(scratch_size, '\0');
				std::snprintf(buf.data(), buf.size(), "%ld", a->AsCount());
				param_values[i] = buf.data();
				break;
				}
			case zeek::TYPE_STRING:
				{
				param_values[i] = a->AsString()->CheckString();
				break;
				}
			default:
				zeek::reporter->Error("Zeek to PQ: arg[%d] %p tag=%d not implemented", i, a,
				                      t->Tag());
			}

		i++;
		}

	PLUGIN_DBG_LOG(plugin, "PQsendQueryParams(nParams=%ld)", args.size());
	int r = PQsendQueryParams(pg_conn.get(), command, args.size(), param_types, param_values.data(),
	                          param_lengths, param_formats, result_format);
	if ( r != 1 )
		emit_builtin_error_pq(pg_conn.get(), "Error with PQsendQuery()");

	return r;
	}

void PQConn::ExpectResult(zeek::detail::trigger::Trigger* arg_trigger,
                          const void* arg_trigger_assoc)
	{
	PLUGIN_DBG_LOG(plugin, "ExpectResult on %p trigger=%p", this, arg_trigger);

	trigger = arg_trigger;
	trigger_assoc = arg_trigger_assoc;

	Process();
	}

// --- PQResult

PQResult::PQResult(PGresult* pg_result)
	: OpaqueVal(opaque_of_pq_result), pg_result(pg_result, PQclear)
	{
	}

zeek::VectorValPtr PQResult::FetchAll()
	{
	PGresult* r = pg_result.get();

	int rows = PQntuples(r);
	int columns = PQnfields(r);

	// Grumble grubmle, would probably be better to have the caller pass
	// in a record type and we will it based on the available fields rather
	// than constructing a new type at runtime...
	auto types = new zeek::type_decl_list;
	for ( int i = 0; i < columns; i++ )
		{
		char* name = PQfname(r, i);
		Oid oid = PQftype(r, i);
		int binary_format = PQfformat(r, i) == 1;
		PLUGIN_DBG_LOG(plugin, "i=%d name=%s oid=%d binary=%d", i, name, oid, binary_format);

		types->push_back(type_decl_for(name, oid));
		}

	auto anonymous_record_type = zeek::make_intrusive<zeek::RecordType>(types);
	auto rt = anonymous_record_type;
	auto anonymous_vector_type = zeek::make_intrusive<zeek::VectorType>(anonymous_record_type);

	auto rval = zeek::make_intrusive<zeek::VectorVal>(anonymous_vector_type);
	for ( int i = 0; i < rows; i++ )
		{
		auto entry = zeek::make_intrusive<zeek::RecordVal>(anonymous_record_type);
		for ( int j = 0; j < columns; j++ )
			{
			if ( PQgetisnull(r, i, j) )
				continue;

			char* value = PQgetvalue(r, i, j);
			int len = PQgetlength(r, i, j);
			PLUGIN_DBG_LOG(plugin, "row=%d column=%d length=%d value=%s", i, j, len, value);

			zeek::ValPtr vptr = val_for(rt->GetFieldType(j)->Tag(), value, len);
			entry->Assign(j, vptr);
			}

		rval->Append(entry);
		}

	return rval;
	}

zeek::ValPtr PQResult::Ntuples()
	{
	return zeek::val_mgr->Count(PQntuples(pg_result.get()));
	}

zeek::ValPtr PQResult::CmdTuples()
	{
	return zeek::val_mgr->Count(atoi(PQcmdTuples(pg_result.get())));
	}

zeek::StringValPtr PQResult::ResStatus()
	{
	ExecStatusType status = PQresultStatus(pg_result.get());
	return zeek::make_intrusive<zeek::StringVal>(PQresStatus(status));
	}

zeek::StringValPtr PQResult::ResultErrorMessage()
	{
	return zeek::make_intrusive<zeek::StringVal>(PQresultErrorMessage(pg_result.get()));
	}
