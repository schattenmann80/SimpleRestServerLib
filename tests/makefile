
INCDIR=-I../include
COMPAILER_OPTIONS= -Wall -ggdb -Werror=format-security -D_FORTIFY_SOURCE=1

DONE=@echo $@ Done

All: MakeDir bin/ParserTests bin/DynamicArrayTest

.PHONY: MakeDir
MakeDir:
	@mkdir -p obj
	@mkdir -p bin

bin/%.o: %.cpp
	@g++ -ggdb -c $< -o $@
	$(DONE)

bin/ParserTests: ParserTests.cpp bin/TestMain.o
	@g++ -ggdb $^ -o $@ -lssl -lcrypto
	$(DONE)

bin/DynamicArrayTest: \
		DynamicArrayTest.cpp \
		obj/DynamicArray.o \
		bin/TestMain.o
	@g++ -ggdb $(INCDIR) $^ -o $@ -lssl -lcrypto
	$(DONE)

obj/%.o: ../src/%.c
	@g++ $(COMPAILER_OPTIONS) $(INCDIR) -c $< -o $@
	$(DONE)