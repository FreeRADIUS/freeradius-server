#ifdef HAVE_OPENSSL_OCSP_H
static conf_parser_t ocsp_config[] = {
	{ FR_CONF_OFFSET("enable", fr_tls_ocsp_conf_t, enable), .dflt = "no" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, fr_tls_ocsp_conf_t, virtual_server),
				    .func = virtual_server_cf_parse,
				    .uctx = &(virtual_server_cf_parse_uctx_t){ .process_module_name = "ocsp"} },

	{ FR_CONF_OFFSET("override_cert_url", fr_tls_ocsp_conf_t, override_url), .dflt = "no" },
	{ FR_CONF_OFFSET("url", fr_tls_ocsp_conf_t, url) },
	{ FR_CONF_OFFSET("use_nonce", fr_tls_ocsp_conf_t, use_nonce), .dflt = "yes" },
	{ FR_CONF_OFFSET("timeout", fr_tls_ocsp_conf_t, timeout), .dflt = "yes" },
	{ FR_CONF_OFFSET("softfail", fr_tls_ocsp_conf_t, softfail), .dflt = "no" },
	{ FR_CONF_OFFSET("verifycert", fr_tls_ocsp_conf_t, verifycert), .dflt = "yes" },

	CONF_PARSER_TERMINATOR
};
#endif

#ifdef HAVE_OPENSSL_OCSP_H
	{ FR_CONF_OFFSET_SUBSECTION("ocsp", 0, fr_tls_conf_t, ocsp, ocsp_config) },

	{ FR_CONF_OFFSET_SUBSCTION("staple", 0, fr_tls_conf_t, staple, ocsp_config) },
#endif

#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp.cache_server) {
		virtual_server_t const *vs;

		vs = virtual_server_find(conf->ocsp.cache_server);
		if (!vs) {
			ERROR("No such virtual server '%s'", conf->ocsp.cache_server);
			goto error;
		}

		if (fr_tls_ocsp_state_cache_compile(&conf->ocsp.cache, vs->server_cs) < 0) goto error;
	}

	if (conf->staple.cache_server) {
		virtual_server_t const *vs;

		vs = virtual_server_find(conf->staple.cache_server);
		if (!vs) {
			ERROR("No such virtual server '%s'", conf->staple.cache_server);
			goto error;
		}

		if (fr_tls_ocsp_staple_cache_compile(&conf->staple.cache, vs->server_cs) < 0) goto error;
	}
#endif

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 *	@fixme:  This is all pretty terrible.
	 *	The stores initialized here are for validating
	 *	OCSP responses.  They have nothing to do with
	 *	verifying other certificates.
	 */

	/*
	 * 	Initialize OCSP Revocation Store
	 */
	if (conf->ocsp.enable) {
		conf->ocsp.store = conf_ocsp_revocation_store(conf);
		if (conf->ocsp.store == NULL) goto error;
	}

	if (conf->staple.enable) {
		conf->staple.store = conf_ocsp_revocation_store(conf);
		if (conf->staple.store == NULL) goto error;
	}
#endif /*HAVE_OPENSSL_OCSP_H*/


static int _conf_server_free(
#if !defined(HAVE_OPENSSL_OCSP_H) && defined(NDEBUG)
			     UNUSED
#endif
			     fr_tls_conf_t *conf)
{
#ifdef HAVE_OPENSSL_OCSP_H
	if (conf->ocsp.store) X509_STORE_free(conf->ocsp.store);
	conf->ocsp.store = NULL;
	if (conf->staple.store) X509_STORE_free(conf->staple.store);
	conf->staple.store = NULL;
#endif

#ifndef NDEBUG
	memset(conf, 0, sizeof(*conf));
#endif
	return 0;
}

/* Session init */
#ifdef HAVE_OPENSSL_OCSP_H
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_OCSP_STORE, (void *)tls_conf->ocsp.store);
#endif

/* Validation checks */
#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 *	Do OCSP last, so we have the complete set of attributes
	 *	available for the virtual server.
	 *
	 *	Fixme: Do we want to store the matching TLS-Client-cert-Filename?
	 */
	if (my_ok && conf->ocsp.enable){
		X509	*issuer_cert;

		RDEBUG2("Starting OCSP Request");

		/*
		 *	If we don't have an issuer, then we can't send
		 *	and OCSP request, but pass the NULL issuer in
		 *	so fr_tls_ocsp_check can decide on the correct
		 *	return code.
		 */
		issuer_cert = X509_STORE_CTX_get0_current_issuer(x509_ctx);
		my_ok = fr_tls_ocsp_check(request, ssl, conf->ocsp.store, issuer_cert, cert, &(conf->ocsp), false);
	}
#endif
