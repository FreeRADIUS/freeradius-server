#ifndef MGCP_PATCH_H
#define MGCP_PATCH_H

#include <osmocom/core/msgb.h>

struct ss7_application;
struct msgb *mgcp_patch(struct ss7_application *app, struct msgb *msg);

#endif
