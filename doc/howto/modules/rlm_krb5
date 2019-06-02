The `rlm_krb5` FreeRADIUS module enables the use of Kerberos 5 for
authentication.

Compilation issues
==================

MIT libraries
-------------

The `rlm_krb5` module, by default, presumes you have the MIT Kerberos 5
distribution. Notes from that distribution:

On linux, you may have to change:

    deplibs_test_method="pass_all"

in `../libtool`

Otherwise, it complains if the krb5 libs aren't shared.

Heimdal libraries
-----------------

If you are using the Heimdal Kerberos 5 distribution, pass an
`--enable-heimdal-krb5` option to `configure`.

Configuration parameters
========================

You can configure the module with the following parameters:

    krb5 {
        # Keytab containing the key used by rlm_krb5
        keytab = /path/to/keytab

        # Principal that is used by rlm_krb5
        service_principal = radius/some.host.com
    }

Make sure the keytab is readable by the user that is used to run `radiusd` and
that your authorization configuration really uses `rlm_krb5` to do the
authentication. You will need to add the following to the 'authenticate'
section of your radiusd.conf file:

    Auth-Type Kerberos {
        krb5
    }
