#pragma once
/* Definitions for register store RPC */

/* Packet types */
#define DATA_REQUEST "RSRQ"
#define DATA_RESPONSE "RSRS"
#define DATA_NOTIFY "RSNO"

/* Request operations (command key) */
#define REG_CMD_LIST "List"
#define REG_CMD_GET "Read"
#define REG_CMD_SET "Write"
#define REG_CMD_SUBSCRIBE "Subscribe"
#define REG_CMD_UNSUBSCRIBE "Unsubscribe"

/* Keys in packet payload */
#define REG_PARAM_COMMAND "Command"
#define REG_PARAM_SEQ "Sequence"
#define REG_PARAM_KEY "Key"
#define REG_PARAM_VALUE "Value"
#define REG_PARAM_ERROR "Error"
#define REG_PARAM_MIN_INTERVAL "Shortest update interval"

#define REG_LIST_ASSIGN ':'
#define REG_LIST_DELIM ';'
#define REG_LIST_TYPE "Type"
#define REG_LIST_MIN_INTERVAL REG_PARAM_MIN_INTERVAL
#define REG_LIST_NEXT_UPDATE "Next update after"
