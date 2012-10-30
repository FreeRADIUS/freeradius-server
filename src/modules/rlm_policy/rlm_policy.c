/*
 * rlm_policy.c		Implements a policy language
 *
 * Version:	$Id$
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
 * Copyright 2004  Alan DeKok <aland@ox.org>
 * Copyright 2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_policy.h"

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "filename",  PW_TYPE_FILENAME,
    offsetof(rlm_policy_t,filename), NULL,  "${confdir}/policy.txt"},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Callbacks for red-black trees.
 */
static int policyname_cmp(const void *a, const void *b)
{
	return strcmp(((const policy_named_t *)a)->name,
		      ((const policy_named_t *)b)->name);
}


/*
 *	Detach a policy.
 */
static int policy_detach(void *instance)
{
	rlm_policy_t *inst = instance;

	if (inst->policies) rbtree_free(inst->policies);
	free(instance);
	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int policy_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_policy_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		policy_detach(inst);
		return -1;
	}

	inst->policies = rbtree_create(policyname_cmp,
				       (void (*)(void *)) rlm_policy_free_item,
				       0);
	if (!inst->policies) {
		policy_detach(inst);
		return -1;
	}

	/*
	 *	Parse the policy from the file.
	 */
	if (!rlm_policy_parse(inst->policies, inst->filename)) {
		policy_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Insert a named policy into a list.
 */
int rlm_policy_insert(rbtree_t *head, policy_named_t *policy)
{
	if (!rbtree_insert(head, policy)) {
		return 0;
	}

	return 1;
}


/*
 *	Find a named policy
 */
policy_named_t *rlm_policy_find(rbtree_t *head, const char *name)
{
	policy_named_t mypolicy;

	mypolicy.name = name;

	return rbtree_finddata(head, &mypolicy);
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int policy_authorize(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "authorize");
}


static int policy_preacct(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "preacct");
}

static int policy_accounting(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "accounting");
}

static int policy_post_auth(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "post-auth");
}

static int policy_pre_proxy(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "pre-proxy");
}

static int policy_post_proxy(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "post-proxy");
}

#ifdef WITH_COA
static int policy_recv_coa(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "recv-coa");
}
static int policy_send_coa(void *instance, REQUEST *request)
{
	return rlm_policy_evaluate((rlm_policy_t *) instance, request,
				   "send-coa");
}
#endif

/*
 *	The "free" functions are here, for no particular reason.
 */
void rlm_policy_free_item(policy_item_t *item)
{
	while (item) {
		policy_item_t *next = item->next;

		switch (item->type) {
		default:
		case POLICY_TYPE_BAD:
			break;

		case POLICY_TYPE_ASSIGNMENT:
			{
				policy_assignment_t *this;

				this = (policy_assignment_t *) item;
				if (this->lhs) free(this->lhs);
				if (this->rhs) free(this->rhs);
			}
			break;

		case POLICY_TYPE_CONDITIONAL:
			{
				policy_condition_t *this;

				this = (policy_condition_t *) item;
				if (this->lhs) free(this->lhs);
				if (this->rhs) free(this->rhs);

				if (this->child) {
					rlm_policy_free_item(this->child);
					this->child = NULL;
				}
			}
			break;

		case POLICY_TYPE_IF:
			{
				policy_if_t *this;

				this = (policy_if_t *) item;
				if (this->condition) {
					rlm_policy_free_item(this->condition);
					this->condition = NULL;
				}
				if (this->if_true) {
					rlm_policy_free_item(this->if_true);
					this->if_true = NULL;
				}
				if (this->if_false) {
					rlm_policy_free_item(this->if_false);
					this->if_false = NULL;
				}
			}
			break;

		case POLICY_TYPE_ATTRIBUTE_LIST:
			{
				policy_attributes_t *this;

				this = (policy_attributes_t *) item;
				rlm_policy_free_item(this->attributes);
			}
			break;

		case POLICY_TYPE_NAMED_POLICY:
			{
				policy_named_t *this;

				this = (policy_named_t *) item;
				rad_assert(this->name != NULL);
				free(this->name);
				rlm_policy_free_item(this->policy);
			}
			break;

		case POLICY_TYPE_CALL:
			{
				policy_call_t *this;

				this = (policy_call_t *) item;
				free(this->name);
			}
			break;

		case POLICY_TYPE_RETURN:
			break;	/* do nothing */

		case POLICY_TYPE_MODULE:
			{
				policy_module_t *this;

				this = (policy_module_t *) item;
				if (this->cs) cf_section_free(&this->cs);
				if (this->mc) modcallable_free(&this->mc);
			}
			break;
		} /* switch over type */
		item->next = NULL; /* for debugging & sanity checks */
		item->type = POLICY_TYPE_BAD;
		free(item);

		item = next;
	}
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_policy = {
	RLM_MODULE_INIT,
	"policy",
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,   	/* type */
	policy_instantiate,		/* instantiation */
	policy_detach,			/* detach */
	{
		NULL,			/* authentication */
		policy_authorize,	/* authorization */
		policy_preacct,		/* preaccounting */
		policy_accounting,	/* accounting */
		NULL,			/* checksimul */
		policy_pre_proxy,	/* pre-proxy */
		policy_post_proxy,	/* post-proxy */
		policy_post_auth	/* post-auth */
#ifdef WITH_COA
		, policy_recv_coa,
		policy_send_coa
#endif
	},
};
