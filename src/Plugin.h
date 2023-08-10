
#pragma once

#include <zeek/OpaqueVal.h>
#include <zeek/Trigger.h>
#include <zeek/broker/Data.h>
#include <zeek/iosource/IOSource.h>
#include <zeek/plugin/Plugin.h>

extern "C"
	{
#include <libpq-fe.h>
	}

namespace plugin
	{
namespace Zeek_PQ
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	void InitPostScript() override;
	};

using Trigger = zeek::detail::trigger::Trigger;

class PQConn : public zeek::OpaqueVal, zeek::iosource::IOSource
	{

public:
	PQConn(PGconn* pg_conn);

	virtual ~PQConn();

	int SendQuery(const char* command);
	int SendQueryParams(const char* command, zeek::ValPList& args);

	/**
	 * Mark this connection as waiting for a result for the given trigger.
	 *
	 */
	void ExpectResult(Trigger* arg_trigger, const void* arg_trigger_assoc);

	// --- iosource
	void Process() override;
	const char* Tag() override;
	double GetNextTimeout() override;

	broker::expected<broker::data> DoSerialize() const override { return broker::ec::invalid_data; }

	bool DoUnserialize(const broker::data& data) override { return false; }

	const char* OpaqueName() const { return "PQ::Conn"; }

	PGconn* GetPGconn() const { return pg_conn.get(); }

private:
	std::unique_ptr<PGconn, void (*)(PGconn*)> pg_conn;

	// Currently active trigger and its association. If this is non-null,
	// then this connection shouldn't be used as another when is pending
	// on it.
	//
	// Maybe with pipelining, but that may not make sense as it'll make
	// command-execution timing non-deterministic.
	Trigger* trigger = nullptr;
	const void* trigger_assoc = nullptr;
	};

class PQResult : public zeek::OpaqueVal
	{

public:
	PQResult(PGresult* pg_result);

	virtual ~PQResult() { }

	zeek::VectorValPtr FetchAll();
	zeek::ValPtr Ntuples();
	zeek::ValPtr CmdTuples();
	zeek::StringValPtr ResStatus();
	zeek::StringValPtr ResultErrorMessage();

	broker::expected<broker::data> DoSerialize() const override { return broker::ec::invalid_data; }

	bool DoUnserialize(const broker::data& data) override { return false; }

	const char* OpaqueName() const { return "PQ::Result"; }

private:
	std::unique_ptr<PGresult, void (*)(PGresult*)> pg_result;
	};

extern Plugin plugin;

	}
	}
