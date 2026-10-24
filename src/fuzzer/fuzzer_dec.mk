FUZZER_NAME		:= fuzzer
# encoder targets have a different FUZZER_ID
FUZZER_ID		:= $(PROTOCOL)
PROTOCOL		:= $(PROTOCOL)

include src/fuzzer/fuzzer.mk
