DONE=@echo $@ Done
COMPAILER_OPTIONS= -Wall -ggdb -Werror=format-security -D_FORTIFY_SOURCE=1

all: \
		bin/ReturnRandNumberHttp \
		bin/ReturnRandNumberHttps
	@echo All Done

bin/ReturnRandNumberHttp: \
		examples/ReturnRandNumberHttp.c \
		obj/SimpleRestServerLib.o
	@gcc $(COMPAILER_OPTIONS) -o $@ $< obj/SimpleRestServerLib.o -lssl -lcrypto
	$(DONE)

bin/ReturnRandNumberHttps: \
		examples/ReturnRandNumberHttps.c \
		obj/SimpleRestServerLib.o
	@gcc $(COMPAILER_OPTIONS) -o $@ $< obj/SimpleRestServerLib.o -lssl -lcrypto
	$(DONE)

obj/%.o: src/%.c
	@gcc $(COMPAILER_OPTIONS) -c $< -o $@
	$(DONE)