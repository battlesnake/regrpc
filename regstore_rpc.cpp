#include <cstd/std.hpp>
#include "regstore_rpc_defs.h"
#include "regstore_rpc.hpp"

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace mark {

regstore_rpc::regstore_rpc(regstore& regs, const send_value& sender) :
	regs(regs),
	sender(sender)
{
}

void regstore_rpc::get(const std::string& remote, const keystore& params, keystore& result)
{
	const auto key = params.at(REG_PARAM_KEY);
	std::string value;
	auto err = regs.get(key, value);
	if (err != regstore::ok) {
		result[REG_PARAM_ERROR] = regstore::errstr(err);
	} else {
		result[REG_PARAM_KEY] = key;
		result[REG_PARAM_VALUE] = value;
	}
}

void regstore_rpc::set(const std::string& remote, const keystore& params, keystore& result)
{
	const auto key = params.at(REG_PARAM_KEY);
	auto err = regs.set(key, params.at(REG_PARAM_VALUE));
	if (err != regstore::ok) {
		result[REG_PARAM_ERROR] = regstore::errstr(err);
	} else {
		result[REG_PARAM_KEY] = key;
		std::string value;
		err = regs.get(key, value);
		if (err == regstore::not_writeable) {
			/* Nothing */
		} else if (err == regstore::ok) {
			result[REG_PARAM_VALUE] = value;
		} else {
			result[REG_PARAM_ERROR] = regstore::errstr(err);
		}
	}
}

void regstore_rpc::subscribe(const std::string& remote, const keystore& params, keystore& result)
{
	const auto key = params.at(REG_PARAM_KEY);
	const auto min_interval = atof(params.at(REG_PARAM_MIN_INTERVAL).c_str());
	const auto obs = [this, remote, key] (const std::string& value) {
		keystore data;
		data[REG_PARAM_KEY] = key;
		data[REG_PARAM_VALUE] = value;
		sender(remote, data);
	};
	regs.observe(key, remote, obs, std::chrono::duration<float>(min_interval));
}

void regstore_rpc::unsubscribe(const std::string& remote, const keystore& params, keystore& result)
{
	const auto key = params.at(REG_PARAM_KEY);
	regs.unobserve(key, remote);
}

bool regstore_rpc::execute(const std::string& remote, const keystore& params, keystore& result)
{
	try {
		const std::string& command = params.at(REG_PARAM_COMMAND);
		result[REG_PARAM_COMMAND] = command;
		if (command == REG_CMD_LIST) {
			list(remote, params, result);
		} else if (command == REG_CMD_GET) {
			get(remote, params, result);
		} else if (command == REG_CMD_SET) {
			set(remote, params, result);
		} else if (command == REG_CMD_SUBSCRIBE) {
			subscribe(remote, params, result);
		} else if (command == REG_CMD_UNSUBSCRIBE) {
			unsubscribe(remote, params, result);
		} else {
			return false;
		}
	} catch (const std::out_of_range&) {
		result.clear();
		result[REG_PARAM_ERROR] = "Required parameter missing";
	} catch (const std::exception&) {
		result.clear();
		result[REG_PARAM_ERROR] = "Operation failed";
		/* Log error TODO */
	}
	const auto seq = params.find(REG_PARAM_SEQ);
	if (seq != params.cend()) {
		result[REG_PARAM_SEQ] = seq->second;
	}
	return true;
}

static std::string fmt_float(double f, int prec)
{
	std::ostringstream ss;
	ss << std::fixed << std::setprecision(prec) << f;
	return ss.rdbuf()->str();
}

template <typename Rep, typename Period>
static std::string fmt_time(const std::chrono::duration<Rep, Period>& t, int prec)
{
	return fmt_float(std::chrono::duration_cast<std::chrono::duration<double>>(t).count(), prec);
}

void regstore_rpc::list(const std::string& remote, const keystore& params, keystore& result)
{
	const auto ls = regs.list();
	for (const auto& kv : ls) {
		const auto& name = kv.first;
		const auto& type = kv.second.type;
		const auto& has_sub = kv.second.subscribed;
		const auto& sub = kv.second.sub_info;
		keystore info(REG_LIST_ASSIGN, REG_LIST_DELIM);
		bool r = !!(type & regstore::rt_readable);
		bool w = !!(type & regstore::rt_writeable);
		info[REG_LIST_TYPE] = std::string(r ? "r" : "") + std::string(w ? "w" : "");
		if (has_sub) {
			info[REG_LIST_MIN_INTERVAL] = fmt_time(sub.min_interval, 6);
			/* TODO: is time_since_epoch using right epoch? */
			info[REG_LIST_NEXT_UPDATE] = fmt_time(sub.next.time_since_epoch(), 6);
		}
		result[name] = info.join();
	}
}

}
