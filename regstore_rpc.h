#pragma once
#include <cstd/std.h>
#include <cstruct/binary_tree.h>
#include <keystore/keystore.h>
#include <regstore/regstore.h>

typedef void regstore_rpc_send_value(void *arg, const struct fstr *remote, const struct keystore *data);

struct regstore_rpc {
	struct regstore *regs;
	regstore_rpc_send_value *sender;
	void *sender_arg;
	struct binary_tree obs_closures;
};

enum regstore_rpc_err {
	regstore_rpc_err_ok,
	regstore_rpc_err_param_missing,
	regstore_rpc_err_fail,
	regstore_rpc_err_unknown_command
};

void regstore_rpc_init(struct regstore_rpc *inst, struct regstore *regs, regstore_rpc_send_value *sender, void *sender_arg);
void regstore_rpc_destroy(struct regstore_rpc *inst);

enum regstore_rpc_err regstore_rpc_list(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);
enum regstore_rpc_err regstore_rpc_get(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);
enum regstore_rpc_err regstore_rpc_set(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);
enum regstore_rpc_err regstore_rpc_subscribe(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);
enum regstore_rpc_err regstore_rpc_unsubscribe(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);

enum regstore_rpc_err regstore_rpc_execute(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result);
