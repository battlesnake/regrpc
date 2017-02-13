#pragma once
/* RPC adapter for interfacing with register store via keystore commands */

#if defined __cplusplus

#include <cstd/std.hpp>
#include <keystore/keystore.hpp>
#include <regstore/regstore.hpp>

namespace mark {

class regstore_rpc {
public:
	using send_value = std::function<void(const std::string& remote, const keystore& data)>;
private:
	regstore& regs;
	send_value sender;
public:
	regstore_rpc(regstore& regs, const send_value& sender);
	void list(const std::string& remote, const keystore& params, keystore& result);
	void get(const std::string& remote, const keystore& params, keystore& result);
	void set(const std::string& remote, const keystore& params, keystore& result);
	void subscribe(const std::string& remote, const keystore& params, keystore& result);
	void unsubscribe(const std::string& remote, const keystore& params, keystore& result);
	bool execute(const std::string& remote, const keystore& params, keystore& result);
};

}

#endif
