SCHEMA_FILES=$(patsubst %.schema,%.ldif,$(wildcard *.schema))

%.ldif: %.schema schema2ldif.sh
	@./schema2ldif.sh $<


.PHONY: all
all: $(SCHEMA_FILES)

.PHONY: clean
clean:
	@rm -rf $(SCHEMA_FILES)
