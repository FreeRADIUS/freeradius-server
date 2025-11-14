#!/bin/sh -e
#
# ### This is a script to setup an openresty web server for testing rlm_rest
#

# on macOS brew tap openresty/brew && brew install openresty

#
# Declare the important path variables
#
PATH="/opt/homebrew/opt/openresty/bin:${PATH}"

# Base Directories
BASEDIR=$(git rev-parse --show-toplevel)
CIDIR="${BASEDIR}/scripts/ci"

BUILDDIR="${BASEDIR}/build/ci/openresty"

# Directories for openresty processes
ROOTDIR="${BUILDDIR}/html"
APIDIR="${BUILDDIR}/api"
LOGDIR="${BUILDDIR}/logs"
CERTDIR="${BUILDDIR}/certs"
CERTSRCDIR="${BASEDIR}/raddb/certs"
PASSWORD="whatever"
HTTP_PORT=8080
HTTPS_PORT=8443

# Important files for running openresty
CONF="${BUILDDIR}/nginx.conf"

# Find the mime.types file
MIME_TYPES_LOCATIONS="/usr/local/openresty/nginx/conf/mime.types /usr/local/etc/openresty/mime.types /opt/homebrew/etc/openresty/mime.types /usr/local/etc/nginx/mime.types /etc/nginx/mime.types"
for i in ${MIME_TYPES_LOCATIONS}; do
	if [ -e "${i}" ]; then
		MIME_TYPES="${i}"
		break
	fi
done

#
# Prepare the directories and files needed for running openresty
#

# Stop any currently running openresty instance
echo "Checking for a running openresty instance"
if [ -e "${LOGDIR}/nginx.pid" ]
then
	echo "Stopping the current openresty instance"
	kill "$(cat ${LOGDIR}/nginx.pid)" || true
	rm -r "${BUILDDIR}"
fi

# Create the directories
mkdir -p "${BUILDDIR}" "${ROOTDIR}" "${APIDIR}" "${LOGDIR}" "${CERTDIR}"

# Create the certificate
echo "Generating the certificates"
openssl pkcs8 -in ${CERTSRCDIR}/rsa/server.key -passin pass:${PASSWORD} -out ${CERTDIR}/server.key
cat ${CERTSRCDIR}/rsa/server.pem ${CERTSRCDIR}/rsa/ca.pem > ${CERTDIR}/server.pem

# Create nginx.conf file
echo "Generating the openresty configuration file"
touch "${CONF}"

# Build nginx.conf
echo "
#
worker_processes  1;
error_log  ${LOGDIR}/error.log;
pid        ${LOGDIR}/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       ${MIME_TYPES};
    default_type  text/plain;

    sendfile      on;

    server {
        listen       ${HTTP_PORT};
	server_name  localhost;

	location / {
	    root   ${ROOTDIR};
	    index  index.html;
	}

	location ~ ^/user(.*)$ {
	    default_type 'application/json';
	    add_header   'Content-Type' 'application/json';
	    content_by_lua_file  ${APIDIR}/json-api.lua;
	}

	location ~ ^/post(.*)$ {
	    content_by_lua_file  ${APIDIR}/post-api.lua;
	}

	location ~ ^/delay(.*)$ {
	    content_by_lua_file  ${APIDIR}/delay-api.lua;
	}

	location ~ ^/fail(.*)$ {
	    content_by_lua_file  ${APIDIR}/fail.lua;
	}
    }

    server {
        listen       ${HTTPS_PORT} ssl;
	server_name  localhost;

	ssl_certificate      ${CERTDIR}/server.pem;
	ssl_certificate_key  ${CERTDIR}/server.key;

	ssl_session_cache    shared:SSL:1m;
	ssl_session_timeout  5m;

	ssl_ciphers  HIGH:!aNULL:!MD5;
	ssl_prefer_server_ciphers  on;

	location / {
	    root   ${ROOTDIR};
	    index  index.html;
	}

        location ~ ^/user(.*)$ {
	    default_type 'application/json';
	    add_header   'Content-Type' 'application/json';
	    content_by_lua_file  ${APIDIR}/json-api.lua;
	}

        location ~ ^/delay/([0-9]*)$ {
	    default_type 'application/json';
	    add_header   'Content-Type' 'application/json';
            content_by_lua_block {
                ngx.sleep(tonumber(ngx.var[1]))
		ngx.say('{\"delay_us\":' .. ngx.ctx.openresty_request_time_us .. '}')
            }
	}

	location ~ ^/post(.*)$ {
	    content_by_lua_file  ${APIDIR}/post-api.lua;
	}

	location ~ ^/auth(.*)$ {
	    content_by_lua_file   ${APIDIR}/auth-api.lua;
	    auth_basic            'Auth Area';
	    auth_basic_user_file  ${BUILDDIR}/.htpasswd;
	}
    }
}

" >"${CONF}"

echo "Copy lua scripts into place"
cp ${CIDIR}/openresty/*.lua "${APIDIR}"

echo "Copy sample data into place"
cp ${CIDIR}/openresty/test.* "${ROOTDIR}"

echo "Copy htpasswd into place"
cp "${CIDIR}/openresty/.htpasswd" "${BUILDDIR}"

#
# Run the openresty instance
#
echo "Starting openresty"
openresty -c ${CONF} -p ${BUILDDIR}
echo "Running openresty on port ${HTTP_PORT} and ${HTTPS_PORT}, accepting all local connections"
cat << EOF
export REST_TEST_SERVER=127.0.0.1
export REST_TEST_SERVER_PORT=${HTTP_PORT}
export REST_TEST_SERVER_SSL_PORT=${HTTPS_PORT}
EOF
