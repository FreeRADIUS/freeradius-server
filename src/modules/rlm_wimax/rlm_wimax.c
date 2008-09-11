/*
 * rlm_wimax.c
 *
 * Version:	$Id$
 *
 * Copyright (C) 2008 Alan DeKok <aland@networkradius.com>
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int wimax_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	vp =  pairfind(request->packet->vps, PW_CALLING_STATION_ID);
	if (vp && (vp->length == 6)) {
		int i;
		uint8_t buffer[6];

		memcpy(buffer, vp->vp_octets, 6);

		/*
		 *	RFC 3580 Section 3.20 says this is the preferred
		 *	format.  Everyone *SANE* is using this format,
		 *	so we fix it here.
		 */
		for (i = 0; i < 6; i++) {
			fr_bin2hex(&buffer[i], &vp->vp_strvalue[i * 3], 1);
			vp->vp_strvalue[(i * 3) + 2] = '-';
		}

		vp->vp_strvalue[(5*3)+2] = '\0';
		vp->length = (5*3)+2;

		RDEBUG2("Fixing WiMAX binary Calling-Station-Id to %s",
			buffer);
	}

	return RLM_MODULE_OK;
}


/*
 *	Massage the request before recording it or proxying it
 */
static int wimax_preacct(void *instance, REQUEST *request)
{
	return wimax_authorize(instance, request);
}

/*
 *	Write accounting information to this modules database.
 */
static int wimax_accounting(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	return RLM_MODULE_OK;
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
module_t rlm_wimax = {
	RLM_MODULE_INIT,
	"wimax",
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		wimax_authorize,	/* authorization */
		wimax_preacct,		/* preaccounting */
		wimax_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL	 		/* post-auth */
	},
};
