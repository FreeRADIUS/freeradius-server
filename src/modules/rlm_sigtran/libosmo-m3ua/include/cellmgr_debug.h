#ifndef CELLMGR_DEBUG_H
#define CELLMGR_DEBUG_H

#define DEBUG
#include <osmocom/core/logging.h>

/* Debuag Areas of the code */
enum {
	DINP,
	DMSC,
	DSCCP,
	DMGCP,
	DISUP,
	DM2UA,
	DPCAP,
};

extern const struct log_info log_info;

#endif
