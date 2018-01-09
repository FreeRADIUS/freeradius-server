#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "okta.h"
#include "util/curl.h"

/**
 * Main struct for holding per-session state.
 */
typedef struct rlm_okta_t
{
	CURL *curl;
	char *state_token;
	char *factor_id;
} rlm_okta_t;

/**
 * @todo: convert some constants to config options
 */
static const CONF_PARSER module_config[] = {
	/* todo: add config options for some of the constants later */
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const char *REPLY_MESSAGE = "Please enter your Google Authenticator token: ";

/**
 * Detects if a given XAuth exchange is a re-auth of an existing sesion.
 * Forewarning: this is kind of silly.
 * In ISAKMP reauths with XAuth, StrongSwan insists on redoing the XAuth step
 * for rekeying. At least with the MacOS client, this manifests as the user's
 * password being appended to itself in the challenge phase. This function
 * detects that we're doing reauth by seeing if the password is duped. See
 * https://wiki.strongswan.org/projects/strongswan/wiki/AppleClients#IKEv1ISAKMP-reauthentication-issues
 * for more detail.
 */
static bool is_xauth_reauth(const char *password)
{
	int len = strlen(password);
	int mid = len / 2;
	return len & 0x1 && strncmp(password, password + mid, mid) == 0;
}

/**
 * Configures the reply as an Access-Challenge.
 */
static void set_access_challenge(REQUEST *request)
{
	char state[64];
	snprintf(state, sizeof(state), "%x", rand());
	pair_make_reply("State", state, T_OP_EQ);
	pair_make_reply("Reply-Message", REPLY_MESSAGE, T_OP_EQ);
	request->reply->code = PW_CODE_ACCESS_CHALLENGE;
}

/**
 * Called at the start of a new RADIUS session.
 */
static int okta_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_okta_t *inst = instance;
	CURLcode ret;

	DEBUG("Initializing new Okta session.");

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK)
	{
		ERROR("CURL init returned error: %i - %s",
			  ret, curl_easy_strerror(ret));

		curl_global_cleanup();
		return -1;
	}

	inst->curl = curl_easy_init();
	if (!inst->curl)
	{
		ERROR("Failed to create CURL handle");
		curl_global_cleanup();
		return -1;
	}

	inst->state_token = NULL;
	inst->factor_id = NULL;
	return 0;
}

/**
 * Performs the FreeRADIUS authorize step.
 * The FreeRADIUS authorize -> authenticate -> accept model is perhaps not
 * the most natural fit for our authentication flow. Our use case more closely
 * resembles authenticate (username/password, first factor) -> authorize
 * (TOTP, second factor) -> accept. This function validates the username
 * and password and, if successful, generates an Access-Challenge for the
 * second factor.
 */
static rlm_rcode_t okta_authorize(void *instance, REQUEST *request)
{
	rlm_okta_t *inst = instance;
	VALUE_PAIR *state, *username, *password;

	DEBUG("Received authorize request");

	username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);
	if (username == NULL || password == NULL)
	{
		ERROR("Missing username/password");
		return RLM_MODULE_REJECT;
	}

	state = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (state == NULL)
	{
		/**
		 * No existing State attribute - proceed with first factor
		 */
		if (authorize_user(inst->curl, username->vp_strvalue, password->vp_strvalue,
						   &(inst->state_token), &(inst->factor_id)))
		{
			DEBUG("RADIUS authorize succeeded. Sending Access-Challenge.");
			set_access_challenge(request);
			return RLM_MODULE_HANDLED;
		} else
		{
			ERROR("Failed authorize");
			return RLM_MODULE_REJECT;
		}
	}

	DEBUG("Found prior state. Continuing on to authenticate.");
	pair_make_config("Auth-Type", "okta", T_OP_EQ);
	return RLM_MODULE_NOOP;
}

/**
 * Performs the FreeRADIUS authenticate step.
 * There are three primary ways this function is currently called:
 *
 * 1) With no State attribute on request (first RADIUS exchange), State set on
 * response. This means we've successfully authorized the user above and need
 * to return the Access-Challenge.
 *
 * 2) With State attribute on request (second RADIUS exchange). We're resuming
 * a prior session and can expect to find the response to the Access-Challenge
 * at the end of the User-Password field.
 *
 * 3) With State attribute on request (second RADIUS exchange), during an
 * ISAKMP SA renegotiation. In this case, the client is not prompted for a
 * second factor so the XAuth protocol ends up with the user's password
 * duplicated during the response to the Access-Challenge. We skip the
 * second factor for reauths.
 */
static rlm_rcode_t okta_authenticate(void *instance, REQUEST *request)
{
	rlm_okta_t *inst		   = instance;
	VALUE_PAIR *request_state  = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
	VALUE_PAIR *response_state = fr_pair_find_by_num(request->reply->vps,  PW_STATE, 0, TAG_ANY);
	VALUE_PAIR *password	   = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);

	DEBUG("Received authenticate request");

	if (request_state != NULL)
	{
		if (is_xauth_reauth(password->vp_strvalue))
		{
			DEBUG("Detected reauth - skipping 2FA");
			return RLM_MODULE_OK;
		}

		/*
		 * Found prior State - proceed with second factor
		 */
		DEBUG("Verifying Access-Challenge response");
		if (verify_challenge_response(inst->curl, password->vp_strvalue,
									  inst->state_token, inst->factor_id))
		{
			return RLM_MODULE_OK;
		}
	}

	if (response_state != NULL)
	{
		DEBUG("Found response state. Continuing.");
		return RLM_MODULE_HANDLED;
	}

	DEBUG("Received authenticate request with no state. Rejecting.");
	return RLM_MODULE_REJECT;
}

/**
 * Called at the end of a RADIUS session.
 * Free any resources consumed during this session.
 */
static int okta_detach(void *instance)
{
	rlm_okta_t *inst = instance;
	DEBUG("okta_detach");
	curl_easy_cleanup(inst->curl);
	free((void*)inst->state_token);
	free((void*)inst->factor_id);
	return 0;
}

/**
 * Configure and export the module's symbol table for dynamic loading.
 */
extern module_t rlm_okta;
module_t rlm_okta		   = {
	.magic				   = RLM_MODULE_INIT,
	.name				   = "okta",
	.type				   = RLM_TYPE_THREAD_SAFE,
	.inst_size			   = sizeof(rlm_okta_t),
	.config				   = module_config,
	.instantiate		   = okta_instantiate,
	.detach				   = okta_detach,
	.methods			   = {
		[MOD_AUTHENTICATE] = okta_authenticate,
		[MOD_AUTHORIZE]    = okta_authorize,
	},
};
