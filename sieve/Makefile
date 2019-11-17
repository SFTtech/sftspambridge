.PHONY: all clean

SVBINS=$(patsubst %.sieve,%.svbin,$(wildcard *.sieve))

all: $(SVBINS)
clean:
	$(RM) $(SVBINS)

%.svbin: %.sieve
	sievec $<
