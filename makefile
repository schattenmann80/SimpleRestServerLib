DONE=@echo $@ Done

all: \
		bin/ReturnRandNumberHttp \
		bin/ReturnRandNumberHttps
	@echo All Done

bin/ReturnRandNumberHttp: \
		examples/ReturnRandNumberHttp.c \
		obj/SimpleRestServerLib.o
	@gcc -ggdb -o $@ $< obj/SimpleRestServerLib.o -lssl -lcrypto
	$(DONE)

bin/ReturnRandNumberHttps: \
		examples/ReturnRandNumberHttps.c \
		obj/SimpleRestServerLib.o
	@gcc -ggdb -o $@ $< obj/SimpleRestServerLib.o -lssl -lcrypto
	$(DONE)

obj/%.o: src/%.c
	@gcc -ggdb -c $< -o $@
	$(DONE)