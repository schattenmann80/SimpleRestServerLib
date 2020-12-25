current_dir := ${CURDIR}

DONE=@echo $@ done
BIN_COMPAILER_OPTIONS= -Wall -ggdb -Werror=format-security -D_FORTIFY_SOURCE=1 -Llib/ -lSimpleRestServer -Wl,-rpath=$(current_dir)/lib
OBJ_COMPAILER_OPTIONS= -Wall -ggdb -Werror=format-security -D_FORTIFY_SOURCE=1 -fPIC

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
	@gcc $(OBJ_COMPAILER_OPTIONS)  $(INCDIR) -c $< -o $@


bin/%: \
		examples/%.c
	@gcc $(BIN_COMPAILER_OPTIONS) -o $@ $^ -lssl -lcrypto
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