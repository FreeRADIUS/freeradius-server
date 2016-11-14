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

#
#  Set the passwords
#
-include passwords.mk

######################################################################
#
#  Make the necessary files, but not client certificates.
#
######################################################################
.PHONY: all
all: index.txt serial dh server ca client ocsp

.PHONY: client
client: client.pem

.PHONY: ca
ca: ca.der

.PHONY: server
server: server.pem server.vrfy

.PHONY: ocsp
ocsp: ocsp.pem ocsp.vrfy

.PHONY: verify
verify: server.vrfy client.vrfy

passwords.mk: server.cnf ca.cnf client.cnf ocsp.cnf
	@echo "PASSWORD_SERVER	= '$(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')'"		> $@
	@echo "PASSWORD_CA	= '$(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_CLIENT	= '$(shell grep output_password client.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_OCSP	= '$(shell grep output_password ocsp.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "USER_NAME	= '$(shell grep emailAddress client.cnf | grep '@' | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "CA_DEFAULT_DAYS  = '$(shell grep default_days ca.cnf | sed 's/.*=//;s/^ *//')'"			>> $@

######################################################################
#
#  Diffie-Hellman parameters
#
######################################################################
dh:
	openssl dhparam -outform PEM -out dh -2 $(DH_KEY_SIZE)

######################################################################
#
#  Create a new self-signed CA certificate
#
######################################################################
ca.key ca.pem: ca.cnf
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	openssl req -new -x509 -keyout ca.key -out ca.pem -config ./ca.cnf -days $(CA_DEFAULT_DAYS)

ca.der: ca.pem
	openssl x509 -inform PEM -outform DER -in ca.pem -out ca.der

######################################################################
#
#  Create a new server certificate, signed by the above CA.
#
######################################################################
server.csr server.key: server.cnf
	openssl req -new  -out server.csr -keyout server.key -config ./server.cnf

server.crt: server.csr ca.key ca.pem
	openssl ca -batch -keyfile ca.key -cert ca.pem -in server.csr -key $(PASSWORD_CA) -out server.crt -config ./server.cnf

server.p12: server.crt
	openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12  -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)

server.pem: server.p12
	openssl pkcs12 -in server.p12 -out server.pem -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)

.PHONY: server.vrfy
server.vrfy: ca.pem
	@openssl verify -CAfile ca.pem server.pem

######################################################################
#
#  Create a new ocsp certificate, signed by the above CA.
#
######################################################################
ocsp.csr ocsp.key: ocsp.cnf
	openssl req -new  -out ocsp.csr -keyout ocsp.key -config ./ocsp.cnf

ocsp.crt: ocsp.csr ca.key ca.pem
	openssl ca -batch -keyfile ca.key -cert ca.pem -in ocsp.csr -key $(PASSWORD_CA) -out ocsp.crt -config ./ocsp.cnf

ocsp.p12: ocsp.crt
	openssl pkcs12 -export -in ocsp.crt -inkey ocsp.key -out ocsp.p12  -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)

ocsp.pem: ocsp.p12
	openssl pkcs12 -in ocsp.p12 -out ocsp.pem -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)

.PHONY: ocsp.vrfy
ocsp.vrfy: ca.pem
	@openssl verify -CAfile ca.pem ocsp.pem

######################################################################
#
#  Create a new client certificate, signed by the the above CA.
#
######################################################################
client.csr client.key: client.cnf
	openssl req -new  -out client.csr -keyout client.key -config ./client.cnf

client.crt: client.csr ca.pem ca.key
	openssl ca -batch -keyfile ca.key -cert ca.pem -in client.csr  -key $(PASSWORD_CA) -out client.crt -config ./client.cnf

client.p12: client.crt
	openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12  -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)

client.pem: client.p12
	openssl pkcs12 -in client.p12 -out client.pem -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	cp client.pem $(USER_NAME).pem

.PHONY: client.vrfy
client.vrfy: ca.pem client.pem
	c_rehash .
	openssl verify -CApath . client.pem

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
	openssl x509 -text -in server.crt

printca:
	openssl x509 -text -in ca.pem

clean:
	@rm -f *~ *old client.csr client.key client.crt client.p12 client.pem

#
#	Make a target that people won't run too often.
#
distclean:
	rm -f *~ dh *.csr *.crt *.p12 *.der *.pem *.key index.txt* \
			serial*  *\.0 *\.1
