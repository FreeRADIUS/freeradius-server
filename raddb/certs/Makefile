######################################################################
#
#	Make file to be installed in /etc/raddb/certs to enable
#	the easy creation of certificates.
#
#	See the README file in this directory for more information.
#	
#	$Id$
#
######################################################################

DH_KEY_SIZE	= 1024

#
#  Set the passwords
#
PASSWORD_SERVER	= $(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')
PASSWORD_CA	= $(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')
PASSWORD_CLIENT	= $(shell grep output_password client.cnf | sed 's/.*=//;s/^ *//')

USER_NAME	= $(shell grep emailAddress client.cnf | grep '@' | sed 's/.*=//;s/^ *//')

######################################################################
#
#  Make the necessary files, but not client certificates.
#
######################################################################
.PHONY: all
all: dh random server ca

.PHONY: client
client: client.pem

.PHONY: ca
ca: ca.pem

.PHONY: server
server: server.pem

######################################################################
#
#  Diffie-Hellman parameters
#
######################################################################
dh:
	openssl dhparam -out dh $(DH_KEY_SIZE)

######################################################################
#
#  Create a new self-signed CA certificate
#
######################################################################
ca.key ca.pem:
	openssl req -new -x509 -keyout ca.key -out ca.pem -config ./ca.cnf 

######################################################################
#
#  Create a new server certificate, signed by the above CA.
#
######################################################################
server.req server.key: 
	openssl req -new  -out server.req -keyout server.key -config ./server.cnf

server.crt: server.req ca.key ca.pem index.txt serial
	openssl ca -batch -keyfile ca.key -cert ca.pem -in server.req  -key $(PASSWORD_CA) -out server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf

server.p12: server.crt
	openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12  -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)

server.pem: server.p12
	openssl pkcs12 -in server.p12 -out server.pem -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)

######################################################################
#
#  Create a new client certificate, signed by the the above server
#  certificate.
#
######################################################################
client.req client.key:
	openssl req -new  -out client.req -keyout client.key -config ./client.cnf

client.crt: client.req server.crt server.key index.txt serial
	openssl ca -batch -keyfile server.key -cert server.crt -in client.req  -key $(PASSWORD_SERVER) -out client.crt -extensions xpclient_ext -extfile xpextensions -config ./client.cnf

client.p12: client.crt
	openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12  -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)

client.pem: client.p12
	openssl pkcs12 -in client.p12 -out client.pem -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_CLIENT)
	cp client.pem $(USER_NAME).pem

######################################################################
#
#  Miscellaneous rules.
#
######################################################################
index.txt:
	@touch index.txt

serial:
	@echo '01' > serial

random:
	@if [ -e /dev/urandom ] ; then \
		dd if=/dev/urandom of=./random count=10 >/dev/null 2>&1; \
	else \
		date > ./random; \
	fi

print:
	openssl x509 -text -in server.crt

clean:
	@rm -f *~ *old client.req client.key client.crt client.p12 client.pem

#
#  Run distclean ONLY if there's a CVS directory, AND it points to
#  cvs.freeradius.org.  Otherwise, it would be easy for administrators
#  to type "make distclean", and destroy their CA and server certificates.
#
distclean:
	@if [ -d CVS -a `grep -i 'cvs\.freeradius\.org' CVS/Root` ] ; then \
		rm -f *~ dh *req *.crt *.p12 *.der *.pem *.key index.txt* \
			serial* random; \
	fi
