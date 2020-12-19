DONE=@echo $@ done
COMPAILER_OPTIONS= -Wall -ggdb -Werror=format-security -D_FORTIFY_SOURCE=1 -Llib/
INCDIR=-Iinclude

all: \
		lib \
		examples
	$(DONE)


.PHONY: lib
lib: \
		MakeDir \
		lib/libSimpleRestServer.so \
		lib/libSimpleRestServer.a
	$(DONE)

.PHONY: examples
examples: \
		MakeDir \
		bin/ReturnRandNumberHttp \
		bin/ReturnRandNumberHttps
	$(DONE)

obj/%.o: src/%.c
	@gcc $(COMPAILER_OPTIONS) -fPIC $(INCDIR) -c $< -o $@


bin/%: \
		examples/%.c
	@gcc $(COMPAILER_OPTIONS) -o $@ $^ -lSimpleRestServer -lssl -lcrypto
	$(DONE)



################## libs #########################

lib/libSimpleRestServer.so: \
		obj/SimpleRestServerLib.o \
		obj/DynamicArray.o
	@gcc $(INCDIR) $^ -shared -fPIC -ggdb -o $@

lib/libSimpleRestServer.a: \
		obj/SimpleRestServerLib.o \
		obj/DynamicArray.o
	@ar -r $@ $^

################## lib end ######################



.PHONY: MakeDir
MakeDir:
	@mkdir -p obj
	@mkdir -p bin
	@mkdir -p lib

.PHONY: clear
clear:
	@rm -rf bin
	@rm -rf obj
	@rm -rf lib
	$(DONE)