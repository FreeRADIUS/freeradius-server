#!/bin/sh -e
#
# ### This is a script to setup an openresty web server for testing rlm_smtp
#

#
# Declare the important path variables
#

# Base Directories
BASEDIR=$(git rev-parse --show-toplevel)
BUILDDIR="${BASEDIR}/build/ci/openresty"
CIDIR="${BASEDIR}/scripts/ci"

# Directories for openresty processes
ROOTDIR="${BUILDDIR}/html"
APIDIR="${BUILDDIR}/api"
LOGDIR="${BUILDDIR}/logs"
CERTDIR="${BUILDDIR}/certs"
CERTSRCDIR="${BASEDIR}/raddb/restcerts"
PASSWORD="whatever"

# Important files for running openresty
CONF="${BUILDDIR}/nginx.conf"

#
# Prepare the directories and files needed for running openresty
#

# Stop any currently running openresty instance
echo "Checking for a running openresty instance"
if [ -e "${LOGDIR}/nginx.pid" ]
then
	echo "Stopping the current openresty instance"
	kill "$(cat ${LOGDIR}/nginx.pid)"
	rm -r "${BUILDDIR}"
fi

# Create the directories
mkdir -p "${BUILDDIR}" "${ROOTDIR}" "${APIDIR}" "${LOGDIR}" "${CERTDIR}"

# Create the certificate
echo "Generating the certificates"
openssl pkcs8 -in ${CERTSRCDIR}/server.key -passin pass:${PASSWORD} -out ${CERTDIR}/server.key
cat ${CERTSRCDIR}/server.pem ${CERTSRCDIR}/ca.pem > ${CERTDIR}/server.pem

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
    include       /usr/local/openresty/nginx/conf/mime.types;
    default_type  text/plain;

    sendfile      on;

    server {
        listen       8080;
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
	    content_by_lua_file ${APIDIR}/delay-api.lua;
	}
    }

    server {
        listen       8443 ssl;
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
cp "${CIDIR}/openresty/test.txt" "${ROOTDIR}"

echo "Copy htpasswd into place"
cp "${CIDIR}/openresty/.htpasswd" "${BUILDDIR}"

#
# Run the openresty instance
#
echo "Starting openresty"
openresty -c ${CONF} -p ${BUILDDIR}
echo "Running openresty on port 8080 and 8443, accepting all local connections"
