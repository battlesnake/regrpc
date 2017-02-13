#if 0
(
set -euo pipefail
declare -r tmp="$(mktemp)"
gcc -DFSTR_FIXED=4 -DTEST_regstore_rpc -DSIMPLE_LOGGING -Wall -Wextra -g -O0 -std=gnu11 -I./c_modules/ -o "$tmp" $(find -name '*.c' -and -not -name '*example*') -lpthread
valgrind --quiet --leak-check=full --track-origins=yes "$tmp"
)
exit 0
#endif
#include <fixedstr/fixedstr.h>
#include <cstruct/binary_tree_iterator.h>
#include "regstore_rpc_defs.h"
#include "regstore_rpc.h"

struct obs_closure {
	struct fstr key;
	struct fstr remote;
	struct regstore_rpc *inst;
};

static int obs_closure_cmp(const void *a, size_t al, const void *b, size_t bl, void *arg)
{
	(void) arg;
	(void) al;
	(void) bl;
	const struct obs_closure *ac = a;
	const struct obs_closure *bc = b;
	int res = fstr_cmp(&ac->remote, &bc->remote);
	if (res) {
		return res;
	}
	return fstr_cmp(&ac->key, &bc->key);
}

void obs_closure_destroy(void *p, size_t length)
{
	(void) length;
	struct obs_closure *c = p;
	fstr_destroy(&c->key);
	fstr_destroy(&c->remote);
}

void regstore_rpc_init(struct regstore_rpc *inst, struct regstore *regs, regstore_rpc_send_value *sender, void *sender_arg)
{
	inst->regs = regs;
	inst->sender = sender;
	inst->sender_arg = sender_arg;
	binary_tree_init(&inst->obs_closures, obs_closure_cmp, NULL, obs_closure_destroy);
}

void regstore_rpc_destroy(struct regstore_rpc *inst)
{
	binary_tree_destroy(&inst->obs_closures);
}

enum regstore_rpc_err regstore_rpc_list(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	(void) params;
	struct binary_tree regs;

	if (!regstore_list(inst->regs, &regs, remote, false)) {
		return regstore_rpc_err_fail;
	}

	struct binary_tree_iterator it;
	binary_tree_iter_init(&it, &regs, false);

	struct regstore_reginfo *reg;
	while ((reg = binary_tree_iter_next(&it, NULL))) {
		struct keystore info;
		keystore_initcustom(&info, 256, 256, REG_LIST_ASSIGN, REG_LIST_DELIM);
		struct fstr fs;
		fstr_init(&fs);
		if (reg->type & rt_readable) {
			fstr_append_from(&fs, "r");
		}
		if (reg->type & rt_writeable) {
			fstr_append_from(&fs, "w");
		}
		keystore_append(&info, REG_LIST_TYPE, fstr_get(&fs));
		if (reg->subscribed) {
			fstr_format(&fs, "%.3f", reg->sub_info.min_interval_ms / 1000.0f);
			keystore_append(&info, REG_LIST_MIN_INTERVAL, fstr_get(&fs));
			fstr_format(&fs, "%.3f" PRIu64, reg->sub_info.next_ms / 1000.0f);
			keystore_append(&info, REG_LIST_NEXT_UPDATE, fstr_get(&fs));
		}
		fstr_destroy(&fs);
		keystore_append(result, fstr_get(&reg->name), keystore_data(&info, NULL));
		keystore_destroy(&info);
	}

	binary_tree_iter_destroy(&it);

	binary_tree_destroy(&regs);

	return regstore_rpc_err_ok;
}

enum regstore_rpc_err regstore_rpc_get(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	(void) remote;

	struct fstr key;
	fstr_init(&key);
	if (!keystore_lookup_cf(params, REG_PARAM_KEY, &key)) {
		fstr_destroy(&key);
		return regstore_rpc_err_param_missing;
	}

	struct fstr value;
	fstr_init(&value);
	enum regstore_err err;
	if ((err = regstore_get(inst->regs, &key, &value)) != regstore_err_ok) {
		fstr_destroy(&value);
		fstr_destroy(&key);
		keystore_append(result, REG_PARAM_ERROR, regstore_errstr(err));
		return regstore_rpc_err_fail;
	}

	keystore_append(result, REG_PARAM_KEY, fstr_get(&key));
	keystore_append(result, REG_PARAM_VALUE, fstr_get(&value));

	fstr_destroy(&value);
	fstr_destroy(&key);

	return regstore_rpc_err_ok;
}

enum regstore_rpc_err regstore_rpc_set(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	(void) remote;

	struct fstr key;
	fstr_init(&key);
	if (!keystore_lookup_cf(params, REG_PARAM_KEY, &key)) {
		fstr_destroy(&key);
		return regstore_rpc_err_param_missing;
	}

	struct fstr value;
	fstr_init(&value);
	if (!keystore_lookup_cf(params, REG_PARAM_VALUE, &value)) {
		fstr_destroy(&key);
		fstr_destroy(&value);
		return regstore_rpc_err_param_missing;
	}

	enum regstore_err err;
	if ((err = regstore_set(inst->regs, &key, &value)) != regstore_err_ok) {
		fstr_destroy(&key);
		fstr_destroy(&value);
		keystore_append(result, REG_PARAM_ERROR, regstore_errstr(err));
		return regstore_rpc_err_fail;
	}

	keystore_append(result, REG_PARAM_KEY, fstr_get(&key));

	enum regstore_rpc_err ret;

	err = regstore_get(inst->regs, &key, &value);
	if (err == regstore_err_not_writeable) {
		/*
		 * TODO: Silent fail on not-writeable?  Copied from CPP version
		 * but sounds like a bad idea
		 */
		ret = regstore_rpc_err_ok;
	} else if (err == regstore_err_ok) {
		keystore_append(result, REG_PARAM_VALUE, fstr_get(&value));
		ret = regstore_rpc_err_ok;
	} else {
		keystore_append(result, REG_PARAM_ERROR, regstore_errstr(err));
		ret = regstore_rpc_err_fail;
	}

	fstr_destroy(&key);
	fstr_destroy(&value);

	return ret;
}

static void obs_send(void *arg, const struct fstr *value)
{
	const struct binary_tree_node *node = arg;
	const struct obs_closure *closure = (const void *) node->data;
	struct keystore data;
	keystore_init(&data, 256, 256);
	keystore_append(&data, REG_PARAM_KEY, fstr_get(&closure->key));
	keystore_append(&data, REG_PARAM_VALUE, fstr_get(value));
	closure->inst->sender(closure->inst->sender_arg, &closure->remote, &data);
	keystore_destroy(&data);
}

enum regstore_rpc_err regstore_rpc_subscribe(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	(void) result;

	struct fstr key;
	fstr_init(&key);
	if (!keystore_lookup_cf(params, REG_PARAM_KEY, &key)) {
		fstr_destroy(&key);
		return regstore_rpc_err_param_missing;
	}

	struct fstr min_interval_f;
	fstr_init(&min_interval_f);
	if (!keystore_lookup_cf(params, REG_PARAM_MIN_INTERVAL, &min_interval_f)) {
		fstr_destroy(&key);
		return regstore_rpc_err_param_missing;
	}
	float min_interval = fstr_read_f(&min_interval_f) * 1000.f;
	if (min_interval < 0 || !isfinite(min_interval)) {
		return regstore_rpc_err_fail;
	} else if (min_interval < 1) {
		min_interval = 1;
	}
	fstr_destroy(&min_interval_f);

	struct obs_closure closure;
	closure.inst = inst;
	fstr_init_copy(&closure.remote, remote);
	fstr_init_copy(&closure.key, &key);
	struct binary_tree_node *arg = *binary_tree_insert(&inst->obs_closures, &closure, sizeof(closure), NULL);
	if (!regstore_observe(inst->regs, &key, remote, obs_send, arg, (int) min_interval)) {
		obs_closure_destroy(&closure, 0);
		fstr_destroy(&key);
		return regstore_rpc_err_fail;
	}

	fstr_destroy(&key);

	return regstore_rpc_err_ok;
}

enum regstore_rpc_err regstore_rpc_unsubscribe(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	(void) result;

	struct fstr key;
	fstr_init(&key);
	if (!keystore_lookup_cf(params, REG_PARAM_KEY, &key)) {
		fstr_destroy(&key);
		return regstore_rpc_err_param_missing;
	}

	if (!regstore_unobserve(inst->regs, &key, remote)) {
		fstr_destroy(&key);
		return regstore_rpc_err_fail;
	}

	struct obs_closure closure;
	closure.inst = inst;
	fstr_init_copy(&closure.remote, remote);
	fstr_init_copy(&closure.key, &key);
	binary_tree_remove(&inst->obs_closures, &closure, sizeof(closure));
	obs_closure_destroy(&closure, 0);

	fstr_destroy(&key);

	return regstore_rpc_err_ok;
}

enum regstore_rpc_err regstore_rpc_execute(struct regstore_rpc *inst, const struct fstr *remote, const struct keystore *params, struct keystore *result)
{
	enum regstore_rpc_err res;

	struct fstr cmd;
	fstr_init(&cmd);
	if (!keystore_lookup_cf(params, REG_PARAM_COMMAND, &cmd)) {
		fstr_destroy(&cmd);
		return false;
	}

	keystore_append(result, REG_PARAM_COMMAND, fstr_get(&cmd));

	if (fstr_eq2(&cmd, REG_CMD_LIST)) {
		res = regstore_rpc_list(inst, remote, params, result);
	} else if (fstr_eq2(&cmd, REG_CMD_GET)) {
		res = regstore_rpc_get(inst, remote, params, result);
	} else if (fstr_eq2(&cmd, REG_CMD_SET)) {
		res = regstore_rpc_set(inst, remote, params, result);
	} else if (fstr_eq2(&cmd, REG_CMD_SUBSCRIBE)) {
		res = regstore_rpc_subscribe(inst, remote, params, result);
	} else if (fstr_eq2(&cmd, REG_CMD_UNSUBSCRIBE)) {
		res = regstore_rpc_unsubscribe(inst, remote, params, result);
	} else {
		res = regstore_rpc_err_unknown_command;
	}

	switch (res) {
	case regstore_rpc_err_ok:
		break;
	case regstore_rpc_err_param_missing:
		keystore_append(result, REG_PARAM_ERROR, "Required parameter missing");
		break;
	case regstore_rpc_err_fail:
		keystore_append(result, REG_PARAM_ERROR, "Operation failed");
		break;
	case regstore_rpc_err_unknown_command:
		keystore_append(result, REG_PARAM_ERROR, "Unknown command");
		break;
	}

	if (keystore_lookup_cf(params, REG_PARAM_SEQ, &cmd)) {
		keystore_append(result, REG_PARAM_SEQ, fstr_get(&cmd));
	}

	fstr_destroy(&cmd);

	return res;
}

#if TEST_regstore_rpc
#include <cstd/unix.h>

static struct regstore regs;
static struct regstore_rpc rpc;

#define priks(data) \
{ \
	struct keystore_iterator it; \
	keystore_iterator_init(&it, data); \
	struct fstr key; \
	struct fstr val; \
	fstr_init(&key); \
	fstr_init(&val); \
	while (keystore_iterator_next_key_f(&it, &key) && \
			keystore_iterator_next_value_f(&it, &val)) { \
		log_info(" * <" PRIfs "> = <" PRIfs ">", prifs(&key), prifs(&val)); \
	} \
	fstr_destroy(&val); \
	fstr_destroy(&key); \
	keystore_iterator_destroy(&it); \
}

static void sender(void *arg, const struct fstr *remote, const struct keystore *data)
{
	(void) arg;
	log_info("");
	log_info("Notification for <" PRIfs ">:", prifs(remote));
	priks(data);
	log_info("");
}

static float temp = 28.4;
static float pres = 1013.25;
static float voltage = 400;
static struct fstr rema;
static struct fstr remb;

#define rand POTATO
static float rand()
{
	return (random() * 1.0f / RAND_MAX) * 2 - 1;
}

static enum regstore_err get_temp(void *arg, struct fstr *value)
{
	(void) arg;
	fstr_format(value, "%.1f", temp + rand() * voltage / 130);
	return regstore_err_ok;
}

static enum regstore_err get_pres(void *arg, struct fstr *value)
{
	(void) arg;
	fstr_format(value, "%.2f", pres + rand() * 10);
	return regstore_err_ok;
}

static enum regstore_err get_voltage(void *arg, struct fstr *value)
{
	(void) arg;
	fstr_format(value, "%.2f", voltage * (100 + rand()) / 100);
	return regstore_err_ok;
}
static enum regstore_err set_voltage(void *arg, const struct fstr *value)
{
	(void) arg;
	voltage = fstr_read_f(value);
	return regstore_err_ok;
}

// MUST BE LONGER THAN FSTR_FIXED!!
#define SFSTR(s) { .data = s, .length = sizeof(s) - 1, .owns = false }

static void rpc_test(struct regstore *rs, struct regstore_rpc *rpc)
{
	struct command {
		const char *message;
		const struct fstr *remote;
		const struct fstr data;
		const char *update;
		const float sleep;
	};
	const struct command script[] = {
		{
			.message = "Reading keys",
			.remote = &rema,
			.data = SFSTR("Command=Read\0Key=Temperature\0")
		},
		{
			.remote = &rema,
			.data = SFSTR("Command=Read\0Key=Pressure\0")
		},
		{
			.remote = &rema,
			.data = SFSTR("Command=Read\0Key=Voltage\0")
		},
		{
			.message = "Subscribing",
			.remote = &rema,
			.data = SFSTR("Command=Subscribe\0Key=Temperature\0Shortest update interval=0.2\0")
		},
		{
			.remote = &remb,
			.data = SFSTR("Command=Subscribe\0Key=Temperature\0Shortest update interval=0.5\0")
		},
		{
			.remote = &rema,
			.data = SFSTR("Command=Subscribe\0Key=Pressure\0Shortest update interval=1.0\0")
		},
		{
			.remote = &remb,
			.data = SFSTR("Command=Subscribe\0Key=Voltage\0Shortest update interval=0.3\0")
		},
		{
			.message = "Updating temperature",
			.update = "Temperature",
			.sleep = 0.1
		},
		{
			.update = "Temperature",
			.sleep = 0.1
		},
		{
			.update = "Temperature",
			.sleep = 0.15
		},
		{
			.update = "Temperature",
			.sleep = 0.1
		},
		{
			.message = "Changing voltage",
			.remote = &rema,
			.data = SFSTR("Command=Write\0Key=Voltage\0Value=11000\0"),
			.sleep = 0.3
		},
		{
			.message = "Updating temperature & pressure",
			.update = "Temperature",
			.sleep = 1
		},
		{
			.update = "Pressure",
			.sleep = 1
		},
		{
			.message = "Unsubscribing from voltage",
			.remote = &remb,
			.data = SFSTR("Command=Unsubscribe\0Key=Voltage\0")
		},
		{
			.message = "Changing voltage",
			.remote = &rema,
			.data = SFSTR("Command=Write\0Key=Voltage\0Value=415\0"),
			.sleep = 0.3
		},
		{
			.message = "Updating temperature",
			.update = "Temperature",
			.sleep = 1
		},
	};
	for (size_t i = 0; i < sizeof(script)/sizeof(script[0]); i++) {
		const struct command *cmd = &script[i];
		if (cmd->message) {
			log_info("");
			log_info("\x1b[1mMessage: %s\x1b[0m", cmd->message);
		}
		if (cmd->remote && cmd->data.length) {
			log_info("");
			struct keystore params;
			keystore_init_from(&params, 256, fstr_get(&cmd->data), fstr_len(&cmd->data));
			struct keystore result;
			keystore_init(&result, 256, 256);
			log_info("Executing command #%zu", i);
			priks(&params);
			regstore_rpc_execute(rpc, cmd->remote, &params, &result);
			keystore_destroy(&result);
			keystore_destroy(&params);
		}
		if (cmd->update) {
			log_info("");
			struct fstr key;
			fstr_init_ref(&key, cmd->update);
			log_info("Updating " PRIfs, prifs(&key));
			regstore_notify(rs, &key);
			fstr_destroy(&key);
		}
		if (cmd->sleep) {
			log_info("");
			log_info("Sleeping for %.2fs", cmd->sleep);
			usleep(cmd->sleep * 1000000);
		}
		log_info("");
	}
}

int main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	fstr_init_ref(&rema, "red");
	fstr_init_ref(&remb, "blue");

	regstore_init(&regs);

	regstore_rpc_init(&rpc, &regs, sender, NULL);

	regstore_add_s(&regs, "Temperature", get_temp, NULL, NULL, NULL);
	regstore_add_s(&regs, "Pressure", get_pres, NULL, NULL, NULL);
	regstore_add_s(&regs, "Voltage", get_voltage, NULL, set_voltage, NULL);

	rpc_test(&regs, &rpc);

	regstore_rpc_destroy(&rpc);
	regstore_destroy(&regs);

	fstr_destroy(&remb);
	fstr_destroy(&rema);

	fstr_destroy(&remb);
	fstr_destroy(&rema);

	return 0;
}
#endif
