RFC	= rfc2865.txt rfc2866.txt rfc2867.txt rfc2868.txt rfc2869.txt \
	  rfc3162.txt 

all: refs
	./rewrite.pl $(RFC)

refs: $(RFC)
	./genref.pl $(RFC) > refs

clean:
	rm -f refs *.html
