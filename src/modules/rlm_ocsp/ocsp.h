/** OCSP Configuration
 *
 */
typedef struct {
	bool		enable;				//!< Enable OCSP checks
	char const	*cache_server;			//!< Virtual server to restore retrieved OCSP status.
	bool		override_url;			//!< Always use the configured OCSP URL even if the
							//!< certificate contains one.
	char const	*url;
	bool		use_nonce;
	X509_STORE	*store;
	uint32_t	timeout;
	bool		softfail;


	fr_tls_cache_t	cache;				//!< Cached cache section pointers.  Means we don't have
							///< to look them up at runtime.
} fr_tls_ocsp_conf_t;

#ifdef HAVE_OPENSSL_OCSP_H
	fr_tls_ocsp_conf_t	ocsp;			//!< Configuration for validating client certificates
							//!< with ocsp.
	fr_tls_ocsp_conf_t	staple;			//!< Configuration for validating server certificates
							//!< with ocsp.
#endif

/*
 *	tls/ocsp.c
 */
int		fr_tls_ocsp_staple_cb(SSL *ssl, void *data);

int		fr_tls_ocsp_check(request_t *request, SSL *ssl,
			       X509_STORE *store, X509 *issuer_cert, X509 *client_cert,
			       fr_tls_ocsp_conf_t *conf, bool staple_response);

int		fr_tls_ocsp_state_cache_compile(fr_tls_cache_t *sections, CONF_SECTION *server_cs);

int		fr_tls_ocsp_staple_cache_compile(fr_tls_cache_t *sections, CONF_SECTION *server_cs);
