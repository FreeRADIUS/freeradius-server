######################################################################
#
#	Make file to be installed in _confdir_/certs to enable
#	the easy creation of certificates.
#
#	See the README file in this directory for more information.
#
#	$Id$
#
######################################################################

DH_KEY_SIZE	= 2048
EXTERNAL_CA	= $(wildcard external_ca.*)

ifneq "$(EXTERNAL_CA)" ""
PARTIAL		= -partial_chain
endif

#
#	Just to mute the WARNING messages complaining about the missing openssl.cnf
#
OPENSSL_CONF := /dev/null
export OPENSSL_CONF

######################################################################
#
#  Make the necessary files, but not client certificates.
#
######################################################################
.PHONY: all
all: index.txt crlnumber serial dh ca server client ocsp

.PHONY: client
client: rsa/client.pem ecc/client.pem rsa/client.crt ecc/client.crt

.PHONY: ca
ca: rsa/ca.der ecc/ca.der rsa/ca.crl rsa/ca.crt ecc/ca.crt

.PHONY: server
server: rsa/server.pem rsa/server.crt rsa/server.vrfy ecc/server.pem ecc/server.crt ecc/server.vrfy

.PHONY: ocsp
ocsp: rsa/ocsp.pem rsa/ocsp.vrfy ecc/ocsp.pem ecc/ocsp.vrfy

.PHONY: inner-server
inner-server: rsa/inner-server.pem rsa/inner-server.vrfy ecc/inner-server.pem ecc/inner-server.vrfy

.PHONY: verify
verify: rsa/server.vrfy rsa/client.vrfy ecc/server.vrfy ecc/client.vrfy

######################################################################
#
#  Set the passwords once, so we don't have to do it on every
#  invocation of "make".
#
######################################################################
passwords.mk: server.cnf ca.cnf client.cnf inner-server.cnf ocsp.cnf
	@echo BUILD passwords.mk
	@echo "PASSWORD_SERVER	= '$(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')'"		> $@
	@echo "PASSWORD_INNER	= '$(shell grep output_password inner-server.cnf | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "PASSWORD_CA	= '$(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_CLIENT	= '$(shell grep output_password client.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "PASSWORD_OCSP	= '$(shell grep output_password ocsp.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "USER_NAME	= '$(shell grep emailAddress client.cnf | grep '@' | sed 's/.*=//;s/^ *//')'"	>> $@
	@echo "CA_DEFAULT_DAYS  = '$(shell grep default_days ca.cnf | sed 's/.*=//;s/^ *//')'"			>> $@

-include passwords.mk

######################################################################
#
#  Output directories
#
######################################################################
OUTPUT_DIRS := rsa/ ecc/

.PHONY: rsa/
rsa/:
	@mkdir -p $@

.PHONY: ecc/
ecc/:
	@mkdir -p $@

######################################################################
#
#  Diffie-Hellman parameters
#
######################################################################
dh:
	openssl dhparam -dsaparam -outform PEM -out dh $(DH_KEY_SIZE)

######################################################################
#
#  Generic rules
#
######################################################################
%.der: %.pem
	openssl x509 -inform PEM -outform DER -in $< -out $@

######################################################################
#
#  Create a new self-signed RSA CA certificate
#
######################################################################
rsa/ca.key rsa/ca.pem: ca.cnf | $(OUTPUT_DIRS)
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	openssl req -new -x509 -keyout rsa/ca.key -out rsa/ca.pem -config ./ca.cnf -days $(CA_DEFAULT_DAYS) \
	-passin pass:$(PASSWORD_CA) -passout pass:$(PASSWORD_CA)
	chmod g+r rsa/ca.key rsa/ca.pem

rsa/ca.crl: rsa/ca.pem
	openssl ca -gencrl -keyfile rsa/ca.key -cert $< -config ./ca.cnf -out rsa/ca-crl.pem -key $(PASSWORD_CA)
	openssl crl -in rsa/ca-crl.pem -outform DER -out $@
	@rm -f rsa/ca-crl.pem

rsa/ca.csr: ca.cnf
	openssl req -new -x509 -keyout rsa/ca.key -out $@ -config ./ca.cnf -days $(CA_DEFAULT_DAYS)

rsa/ca.crt: rsa/ca.pem
	openssl x509 -outform DER -in $< -out $@


######################################################################
#
#  Create a new self-signed ECC CA certificate
#
######################################################################
ecc/ca.key: ca.cnf | $(OUTPUT_DIRS)
	openssl ecparam -out $@ -name prime256v1 -genkey

ecc/ca.der: ecc/ca.pem
	openssl x509 -inform PEM -outform DER -in $< -out $@

ecc/ca.pem: ecc/ca.key
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	openssl req -new -x509 -key $< -out $@ -config ./ca.cnf -days $(CA_DEFAULT_DAYS)

ecc/ca.crt: ecc/ca.pem
	openssl x509 -outform DER -in $< -out $@


######################################################################
#
#  Create a new server certificate, signed by the above RSA CA.
#
######################################################################
rsa/server.csr rsa/server.key: server.cnf | $(OUTPUT_DIRS)
	openssl req -new -out rsa/server.csr -keyout rsa/server.key -config ./server.cnf
	chmod g+r rsa/server.key

rsa/server.crt: rsa/ca.key rsa/ca.pem rsa/server.csr
	openssl ca -batch -keyfile rsa/ca.key -cert rsa/ca.pem -in rsa/server.csr -key $(PASSWORD_CA) -out $@ -config ./server.cnf

rsa/server.p12: rsa/server.crt
	openssl pkcs12 -export -in $< -inkey rsa/server.key -out $@ -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r $@

rsa/server.pem: rsa/server.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r $@

.PHONY: rsa/server.vrfy
rsa/server.vrfy: rsa/ca.pem rsa/server.pem
	@openssl verify $(PARTIAL) -CAfile rsa/ca.pem rsa/server.pem

######################################################################
#
#  Create a new server certificate, signed by the above ECC CA.
#
######################################################################
ecc/server.key: server.cnf | $(OUTPUT_DIRS)
	openssl ecparam -out $@ -name prime256v1 -genkey
	chmod g+r $@

ecc/server.csr: ecc/server.key
	openssl req -new -out $@ -key $< -config ./server.cnf

ecc/server.crt: ecc/ca.key ecc/ca.pem ecc/server.csr
	openssl ca -batch -keyfile ecc/ca.key -cert ecc/ca.pem -in ecc/server.csr -key $(PASSWORD_CA) -out $@ -config ./server.cnf

ecc/server.p12: ecc/server.crt
	openssl pkcs12 -export -in $< -inkey ecc/server.key -out $@ -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r $@

ecc/server.pem: ecc/server.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_SERVER) -passout pass:$(PASSWORD_SERVER)
	chmod g+r $@

.PHONY: ecc/server.vrfy
ecc/server.vrfy: ecc/ca.pem ecc/server.pem
	@openssl verify $(PARTIAL) -CAfile ecc/ca.pem ecc/server.pem

######################################################################
#
#  Create a new ocsp certificate, signed by the above RSA CA.
#
######################################################################
rsa/ocsp.csr rsa/ocsp.key: ocsp.cnf | $(OUTPUT_DIRS)
	openssl req -new -out rsa/ocsp.csr -keyout rsa/ocsp.key -config ./ocsp.cnf
	chmod g+r rsa/ocsp.key

rsa/ocsp.crt: rsa/ca.key rsa/ca.pem rsa/ocsp.csr
	openssl ca -batch -keyfile rsa/ca.key -cert rsa/ca.pem -in rsa/ocsp.csr -key $(PASSWORD_CA) -out $@ -config ./ocsp.cnf

rsa/ocsp.p12: rsa/ocsp.crt
	openssl pkcs12 -export -in $< -inkey rsa/ocsp.key -out $@ -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)
	chmod g+r $@

rsa/ocsp.pem: rsa/ocsp.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)
	chmod g+r $@

.PHONY: rsa/ocsp.vrfy
rsa/ocsp.vrfy: rsa/ca.pem rsa/ocsp.pem
	@openssl verify $(PARTIAL) -CAfile rsa/ca.pem rsa/ocsp.pem

######################################################################
#
#  Create a new ocsp certificate, signed by the above ECC CA.
#
######################################################################
ecc/ocsp.key: ocsp.cnf | $(OUTPUT_DIRS)
	openssl ecparam -out $@ -name prime256v1 -genkey
	chmod g+r $@

ecc/ocsp.csr: ecc/ocsp.key
	openssl req -new -out $@ -key ecc/ocsp.key -config ./ocsp.cnf

ecc/ocsp.crt: ecc/ca.key ecc/ca.pem ecc/ocsp.csr
	openssl ca -batch -keyfile ecc/ca.key -cert ecc/ca.pem -in ecc/ocsp.csr -key $(PASSWORD_CA) -out $@ -config ./ocsp.cnf

ecc/ocsp.p12: ecc/ocsp.crt
	openssl pkcs12 -export -in $< -inkey ecc/ocsp.key -out $@ -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)
	chmod g+r $@

ecc/ocsp.pem: ecc/ocsp.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_OCSP) -passout pass:$(PASSWORD_OCSP)
	chmod g+r $@

.PHONY: ecc/ocsp.vrfy
ecc/ocsp.vrfy: ecc/ca.pem ecc/ocsp.pem
	@openssl verify $(PARTIAL) -CAfile ecc/ca.pem ecc/ocsp.pem

######################################################################
#
#  Create a new client certificate, signed by the the above RSA CA.
#
######################################################################
rsa/client.csr rsa/client.key: client.cnf | $(OUTPUT_DIRS)
	openssl req -new -out rsa/client.csr -keyout rsa/client.key -config ./client.cnf
	chmod g+r rsa/client.key

rsa/client.crt: rsa/ca.pem rsa/ca.key rsa/client.csr
	openssl ca -batch -keyfile rsa/ca.key -cert rsa/ca.pem -in rsa/client.csr -key $(PASSWORD_CA) -out $@ -config ./client.cnf

rsa/client.p12: rsa/client.crt
	openssl pkcs12 -export -in $< -inkey rsa/client.key -out $@ -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r $@

rsa/client.pem: rsa/client.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r $@
	cp rsa/client.pem $(USER_NAME).pem

.PHONY: rsa/client.vrfy
rsa/client.vrfy: rsa/ca.pem rsa/client.pem
	c_rehash rsa/
	openssl verify -CApath rsa/ rsa/client.pem

######################################################################
#
#  Create a new client certificate, signed by the the above ECC CA.
#
######################################################################
ecc/client.key: client.cnf | $(OUTPUT_DIRS)
	openssl ecparam -out $@ -name prime256v1 -genkey
	chmod g+r $@

ecc/client.csr: ecc/client.key
	openssl req -new -out $@ -key ecc/client.key -config ./client.cnf

ecc/client.crt: ecc/ca.pem ecc/ca.key ecc/client.csr
	openssl ca -batch -keyfile ecc/ca.key -cert ecc/ca.pem -in ecc/client.csr -key $(PASSWORD_CA) -out $@ -config ./client.cnf

ecc/client.p12: ecc/client.crt
	openssl pkcs12 -export -in $< -inkey ecc/client.key -out $@ -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r $@

ecc/client.pem: ecc/client.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_CLIENT) -passout pass:$(PASSWORD_CLIENT)
	chmod g+r $@
	cp ecc/client.pem $(USER_NAME).ecc.pem

.PHONY: ecc/client.vrfy
ecc/client.vrfy: ecc/ca.pem ecc/client.pem
	c_rehash ecc/
	openssl verify -CApath ecc/ ecc/client.pem

######################################################################
#
#  Create a new inner-server certificate, signed by the above RSA CA.
#
######################################################################
rsa/inner-server.csr rsa/inner-server.key: inner-server.cnf | $(OUTPUT_DIRS)
	openssl req -new -out rsa/inner-server.csr -keyout rsa/inner-server.key -config ./inner-server.cnf
	chmod g+r rsa/inner-server.key

rsa/inner-server.crt: rsa/ca.key rsa/ca.pem rsa/inner-server.csr
	openssl ca -batch -keyfile rsa/ca.key -cert rsa/ca.pem -in rsa/inner-server.csr -key $(PASSWORD_CA) -out $@ -extensions xpserver_ext -extfile xpextensions -config ./inner-server.cnf

rsa/inner-server.p12: rsa/inner-server.crt
	openssl pkcs12 -export -in $< -inkey rsa/inner-server.key -out $@ -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r $@

rsa/inner-server.pem: rsa/inner-server.p12
	openssl pkcs12 -in $< -out $@ -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r $@

.PHONY: rsa/inner-server.vrfy
rsa/inner-server.vrfy: rsa/ca.pem
	@openssl verify $(PARTIAL) -CAfile rsa/ca.pem rsa/inner-server.pem

######################################################################
#
#  Create a new inner-server certificate, signed by the above ECC CA.
#
######################################################################
ecc/inner-server.key: inner-server.cnf | $(OUTPUT_DIRS)
	openssl ecparam -out ecc/inner-server.key -name prime256v1 -genkey
	chmod g+r $@

ecc/inner-server.csr: ecc/inner-server.key
	openssl req -new -out $@ -key ecc/inner-server.key -config ./inner-server.cnf
	chmod g+r $@

ecc/inner-server.crt: ecc/ca.key ecc/ca.pem ecc/inner-server.csr
	openssl ca -batch -keyfile ecc/ca.key -cert ecc/ca.pem -in ecc/inner-server.csr -key $(PASSWORD_CA) -out $@ -extensions xpserver_ext -extfile xpextensions -config ./inner-server.cnf

ecc/inner-server.p12: ecc/inner-server.crt
	openssl pkcs12 -export -in $< -inkey ecc/inner-server.key -out $@ -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r $@

ecc/inner-server.pem: ecc/inner-server.p12
	openssl pkcs12 -in $<< -out $@ -passin pass:$(PASSWORD_INNER) -passout pass:$(PASSWORD_INNER)
	chmod g+r $@

.PHONY: ecc/inner-server.vrfy
ecc/inner-server.vrfy: ecc/ca.pem
	@openssl verify $(PARTIAL) -CAfile ecc/ca.pem ecc/inner-server.pem

######################################################################
#
#  Miscellaneous rules.
#
######################################################################
index.txt:
	@touch index.txt

crlnumber:
	@echo '01' > crlnumber

serial:
	@echo '01' > serial

print:
	openssl x509 -text -in rsa/server.crt
	openssl x509 -text -in ecc/server.crt

printca:
	openssl x509 -text -in rsa/ca.pem
	openssl x509 -text -in ecc/ca.pem

clean:
	@rm -f *~ *old rsa/client.* ecc/client.*

#
#	Make a target that people won't run too often.
#
distclean:
	rm -rf *~ *.pem dh ecc/ rsa/ passwords.mk index.txt* serial*  *\.0 *\.1
