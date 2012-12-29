/*
 * 	 rlm_acctlog.c
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *   Copyright 2006 Suntel Communications - www.suntel.com.tr
 *   Copyright 2006 The FreeRADIUS server project
 *
 *   Tuyan Ozipek
 *   Peter Nixon
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

typedef struct rlm_acctlog_t {
    char        *acctstart;
    char        *acctstop;
	char		*acctupdate;
    char        *accton;
	char		*acctoff;

} rlm_acctlog_t;

static const CONF_PARSER module_config[] = {
    { "acctlog_update",  PW_TYPE_STRING_PTR, offsetof(rlm_acctlog_t, acctupdate), NULL,  ""},
    { "acctlog_start",  PW_TYPE_STRING_PTR, offsetof(rlm_acctlog_t, acctstart), NULL,  ""},
    { "acctlog_stop",  PW_TYPE_STRING_PTR, offsetof(rlm_acctlog_t, acctstop), NULL,  ""},
    { "acctlog_on",  PW_TYPE_STRING_PTR, offsetof(rlm_acctlog_t, accton), NULL,  ""},
    { "acctlog_off",  PW_TYPE_STRING_PTR, offsetof(rlm_acctlog_t, acctoff), NULL,  ""},
    { NULL, -1, 0, NULL, NULL }     /* end the list */
};


static int acctlog_detach(void *instance)
{
    rlm_acctlog_t *inst = instance;


    free(inst);
    return 0;
}

static int acctlog_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_acctlog_t *inst;

    inst = rad_malloc(sizeof(*inst));
    memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		acctlog_detach(inst);
		return -1;
	}

	*instance = inst;

    return 0;

}

static int do_acctlog_acct(void *instance, REQUEST *request)
{
	rlm_acctlog_t *inst;
	VALUE_PAIR *pair;

	char    logstr[1024];
	int     acctstatustype = 0;


	inst = (rlm_acctlog_t*) instance;

    if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) != NULL) {
        acctstatustype = pair->vp_integer;
    } else {
        radius_xlat(logstr, sizeof(logstr), "packet has no accounting status type. [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, NULL, NULL);
        radlog(L_ERR, "rlm_acctlog (%s)", logstr);
        return RLM_MODULE_INVALID;
    }

	switch (acctstatustype) {
		case PW_STATUS_START:
			radius_xlat(logstr, sizeof(logstr), inst->acctstart, request, NULL, NULL);
		break;
		case PW_STATUS_STOP:
			radius_xlat(logstr, sizeof(logstr), inst->acctstop, request, NULL, NULL);
		break;
		case PW_STATUS_ALIVE:
			radius_xlat(logstr, sizeof(logstr), inst->acctupdate, request, NULL, NULL);
		break;
		case PW_STATUS_ACCOUNTING_ON:
			radius_xlat(logstr, sizeof(logstr), inst->accton, request, NULL, NULL);
		break;
		case PW_STATUS_ACCOUNTING_OFF:
			radius_xlat(logstr, sizeof(logstr), inst->acctoff, request, NULL, NULL);
		break;

	default:
		*logstr = 0;

	}

	if (*logstr) radlog(L_ACCT,"%s", logstr);

	return RLM_MODULE_OK;
}

/*
 *  Externally visible module definition.
 */
module_t rlm_acctlog = {
    RLM_MODULE_INIT,
    "acctlog",
    RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
    acctlog_instantiate,        /* instantiation */
    acctlog_detach,         /* detach */
    {
        NULL, /* authentication */
        NULL, /* authorization */
        NULL, /* preaccounting */
        do_acctlog_acct, /* accounting */
        NULL,       /* checksimul */
        NULL,     /* pre-proxy */
        NULL, /* post-proxy */
        NULL  /* post-auth */
    },
};

