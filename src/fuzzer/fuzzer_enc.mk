FUZZER_NAME		:= fuzzer_enc
FUZZER_ID		:= enc_$(PROTOCOL)
PROTOCOL		:= $(PROTOCOL)

include src/fuzzer/fuzzer.mk
