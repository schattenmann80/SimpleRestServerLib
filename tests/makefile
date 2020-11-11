
All: bin/ParserTests

bin/%.o: %.cpp
	@g++ -ggdb -c $< -o $@
	$(DONE)

bin/ParserTests: ParserTests.cpp bin/TestMain.o
	@g++ -ggdb $^ -o $@ -lssl -lcrypto