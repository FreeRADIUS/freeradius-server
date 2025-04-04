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

DH_KEY_SIZE	= 2048
OPENSSL		= openssl
EXTERNAL_CA	= $(wildcard external_ca.*)

ifneq "$(EXTERNAL_CA)" ""
PARTIAL		= -partial_chain
endif

#
#  Set the passwords
#
include passwords.mk

######################################################################
#
#  Make the necessary files, but not client certificates.
#
######################################################################
.PHONY: all
all: index.txt serial ca server client

.PHONY: client
client: client.pem

.PHONY: ca
ca: ca.der ca.crl

.PHONY: server
server: server.pem server.vrfy

.PHONY: inner-server
inner-server: inner-server.pem inner-server.vrfy

.PHONY: verify
verify: server.vrfy client.vrfy

passwords.mk: server.cnf ca.cnf client.cnf inner-server.cnf
	@echo "PASSWORD_SERVER	= '$(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')'"		> $@
	@echo "PASSWORD_INNER	= '$(shell grep output_password inner-server.cnf | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "PASSWORD_CA	= '$(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_CLIENT	= '$(shell grep output_password client.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "USER_NAME	= '$(shell grep emailAddress client.cnf | grep '@' | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "CA_DEFAULT_DAYS  = '$(shell grep default_days ca.cnf | sed 's/.*=//;s/^ *//')'"			>> $@

######################################################################
#
#  Diffie-Hellman parameters
#
######################################################################
dh:
	$(OPENSSL) dhparam -out dh -2 $(DH_KEY_SIZE)

######################################################################
#
#  Create a new self-signed CA certificate
#
######################################################################
ca.key ca.pem: ca.cnf
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	$(OPENSSL) req -new -x509 -keyout ca.key -out ca.pem \
		-days $(CA_DEFAULT_DAYS) -config ./ca.cnf \
		-passin pass:$(PASSWORD_CA) -passout pass:$(PASSWORD_CA)
	chmod g+r ca.key

ca.der: ca.pem
	$(OPENSSL) x509 -inform PEM -outform DER -in ca.pem -out ca.der

ca.crl: ca.pem
	$(OPENSSL) ca -gencrl -keyfile ca.key -cert ca.pem -config ./ca.cnf -out ca-crl.pem -key $(PASSWORD_CA)
	$(OPENSSL) crl -in ca-crl.pem -outform der -out ca.crl
	rm ca-crl.pem

######################################################################
#
#  Create a new server certificate, signed by the above CA.
#
######################################################################
server.csr server.key: server.cnf
	$(OPENSSL) req -new  -out server.csr -keyout server.key -config ./server.cnf
	chmod g+r server.key

server.crt: ca.key ca.pem server.csr
	$(OPENSSL) ca -batch -keyfile ca.key -cert ca.pem -in server.csr  -key $(PASSWORD_CA) -out server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf

server.p12: server.crt
	$(OPENSSL) pkcs12 -export -in server.crt -inkey server.key -out server.p12  -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r server.p12

server.der: server.pem
	$(OPENSSL) x509 -inform PEM -outform DER -in server.pem -out server.der

server.pem: server.p12
	$(OPENSSL) pkcs12 -in server.p12 -out server.pem -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r server.pem

.PHONY: server.vrfy
server.vrfy: ca.pem
	@$(OPENSSL) verify $(PARTIAL) -CAfile ca.pem server.pem

######################################################################
#
#  Create a new client certificate, signed by the the above server
#  certificate.
#
######################################################################
client.csr client.key: client.cnf
	$(OPENSSL) req -new  -out client.csr -keyout client.key -config ./client.cnf
	chmod g+r client.key

client.crt: ca.key ca.pem client.csr
	$(OPENSSL) ca -batch -keyfile ca.key -cert ca.pem -in client.csr  -key $(PASSWORD_CA) -out client.crt -extensions xpclient_ext -extfile xpextensions -config ./client.cnf

client.p12: client.crt
	$(OPENSSL) pkcs12 -export -in client.crt -inkey client.key -out client.p12  -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r client.p12
	cp client.p12 $(USER_NAME).p12

client.pem: client.p12
	$(OPENSSL) pkcs12 -in client.p12 -out client.pem -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r client.pem
	cp client.pem $(USER_NAME).pem

.PHONY: client.vrfy
client.vrfy: ca.pem client.pem
	c_rehash .
	$(OPENSSL) verify -CApath . client.pem

######################################################################
#
#  Create a new inner-server certificate, signed by the above CA.
#
######################################################################
inner-server.csr inner-server.key: inner-server.cnf
	$(OPENSSL) req -new  -out inner-server.csr -keyout inner-server.key -config ./inner-server.cnf
	chmod g+r inner-server.key

inner-server.crt: ca.key ca.pem inner-server.csr
	$(OPENSSL) ca -batch -keyfile ca.key -cert ca.pem -in inner-server.csr  -key $(PASSWORD_CA) -out inner-server.crt -extensions xpserver_ext -extfile xpextensions -config ./inner-server.cnf

inner-server.p12: inner-server.crt
	$(OPENSSL) pkcs12 -export -in inner-server.crt -inkey inner-server.key -out inner-server.p12  -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r inner-server.p12

inner-server.pem: inner-server.p12
	$(OPENSSL) pkcs12 -in inner-server.p12 -out inner-server.pem -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r inner-server.pem

.PHONY: inner-server.vrfy
inner-server.vrfy: ca.pem
	@$(OPENSSL) verify $(PARTIAL) -CAfile ca.pem inner-server.pem

######################################################################
#
#  Miscellaneous rules.
#
######################################################################
index.txt:
	@touch index.txt

serial:
	@echo '01' > serial

print:
	$(OPENSSL) x509 -text -in server.crt

printca:
	$(OPENSSL) x509 -text -in ca.pem

clean:
	@rm -f *~ *old client.csr client.key client.crt client.p12 client.pem

#
#	Make a target that people won't run too often.
#
destroycerts:
	rm -f *~ dh *.csr *.crt *.p12 *.der *.pem *.key index.txt* \
			serial*  *\.0 *\.1 ca-crl.pem ca.crl
