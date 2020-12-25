#include "../src/SimpleRestServerLib.c"
#include "catch2/catch.hpp"
#include <string>

TEST_CASE("Test parse_url_arguments")
{
	RSL_ClientRequest sClientRequest;

	SECTION( "No arguments" )
	{
		sClientRequest.pszUrl = strdup("/");

		parse_url_arguments( &sClientRequest );

		REQUIRE( sClientRequest.iArgumentCount == 0 );

		free( sClientRequest.pszUrl );
	}

	SECTION( "One argument" )
	{
		sClientRequest.pszUrl = strdup("/?arg1=val1");

		parse_url_arguments( &sClientRequest );

		REQUIRE( sClientRequest.iArgumentCount == 1 );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszKey) == std::string("arg1")  );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszValue) == std::string("val1")  );

		REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("/") );

		free( sClientRequest.pszUrl );
		free( sClientRequest.pArguments );
	}

	SECTION( "two argument" )
	{
		sClientRequest.pszUrl = strdup("/?arg1=val1&arg2=val2");

		parse_url_arguments( &sClientRequest );

		REQUIRE( sClientRequest.iArgumentCount == 2 );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszKey) == std::string("arg1")  );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszValue) == std::string("val1")  );

		REQUIRE( std::string(sClientRequest.pArguments[1].pszKey) == std::string("arg2")  );
		REQUIRE( std::string(sClientRequest.pArguments[1].pszValue) == std::string("val2")  );

		REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("/") );

		free( sClientRequest.pszUrl );
		free( sClientRequest.pArguments );
	}

	SECTION( "three argument" )
	{
		sClientRequest.pszUrl = strdup("/?arg1=val1&arg2=val2&something=crazy");

		parse_url_arguments( &sClientRequest );

		REQUIRE( sClientRequest.iArgumentCount == 3 );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszKey) == std::string("arg1")  );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszValue) == std::string("val1")  );

		REQUIRE( std::string(sClientRequest.pArguments[1].pszKey) == std::string("arg2")  );
		REQUIRE( std::string(sClientRequest.pArguments[1].pszValue) == std::string("val2")  );

		REQUIRE( std::string(sClientRequest.pArguments[2].pszKey) == std::string("something")  );
		REQUIRE( std::string(sClientRequest.pArguments[2].pszValue) == std::string("crazy")  );

		REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("/") );

		free( sClientRequest.pszUrl );
		free( sClientRequest.pArguments );
	}

	SECTION( "Test with different url")
	{
		sClientRequest.pszUrl = strdup("abcde1/and/?arg1=val1&arg2=val2");

		parse_url_arguments( &sClientRequest );

		REQUIRE( sClientRequest.iArgumentCount == 2 );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszKey) == std::string("arg1")  );
		REQUIRE( std::string(sClientRequest.pArguments[0].pszValue) == std::string("val1")  );

		REQUIRE( std::string(sClientRequest.pArguments[1].pszKey) == std::string("arg2")  );
		REQUIRE( std::string(sClientRequest.pArguments[1].pszValue) == std::string("val2")  );

		REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("abcde1/and/") );

		free( sClientRequest.pszUrl );
		free( sClientRequest.pArguments );
	}

	// SECTION( "Wrong input: to much =" )
	// {
	// 	sClientRequest.pszUrl = strdup("abcde1/and/?arg1==val1=&=arg2=val2");

	// 	parse_url_arguments( &sClientRequest );

	// 	REQUIRE( sClientRequest.iArgumentCount == 0 );

	// 	REQUIRE( sClientRequest.iArgumentParseError == 1 );

	// 	REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("abcde1/and/") );

	// 	free( sClientRequest.pszUrl );
	// }

	// SECTION( "Wrong input: to much &" )
	// {
	// 	sClientRequest.pszUrl = strdup("abcde1/and/?arg1&=val1&arg2&&=val2&");

	// 	parse_url_arguments( &sClientRequest );

	// 	REQUIRE( sClientRequest.iArgumentCount == 0 );

	// 	REQUIRE( sClientRequest.iArgumentParseError == 1 );

	// 	REQUIRE( std::string( sClientRequest.pszUrl ) == std::string("abcde1/and/") );

	// 	free( sClientRequest.pszUrl );
	// }

}

TEST_CASE( "Test parse_http_request2")
{
	char input[] = "GET /infotext.html HTTP/1.1\r\nHost: www.example.net\r\n\r\n";

	const char* test[] = { "GET", "/infotext.html", "HTTP/1.1", "Host: www.example.net", "" };

	DynamicArray *vecTokens = split_http_request( input );

	REQUIRE( DA_size( vecTokens ) == 5 );

	for( int cnt = 0; vecTokens != NULL && cnt < DA_size( vecTokens); cnt++ )
	{
		REQUIRE( std::string( DA_GET( vecTokens, char*, cnt)) == std::string(test[cnt]) );
	}
}

TEST_CASE( "Test parse_http_request" )
{
	SECTION( "Test1" )
	{
		RSL_ClientData sClientData;
		RSL_ClientRequest sClientRequest;

		const char input[] = "GET /infotext.html HTTP/1.1\r\nHost: www.example.net\r\n\r\n";

		sClientData.pRequestString = DA_Init( TYPE_CHAR );
		DA_add_range( sClientData.pRequestString, strlen(input) + 1, input );

		parse_http_request( &sClientData, &sClientRequest );

		REQUIRE( std::string("GET") == std::string( sClientRequest.pszRequestMethod ) );
		REQUIRE( std::string("/infotext.html") == std::string( sClientRequest.pszUrl ) );
		REQUIRE( std::string("HTTP/1.1") == std::string( sClientRequest.pszHttpVerison ) );
		REQUIRE( std::string("Host: www.example.net") == std::string( sClientRequest.pszHeaderArguments ) );
		REQUIRE( std::string("") == std::string( sClientRequest.pszBody ) );
	}
}

TEST_CASE( "Test split_string" )
{
	SECTION("Empty")
	{
		char input[32] = "";
		DynamicArray *vec = split_string(input, ' ');

		REQUIRE( vec == NULL );
	}

	SECTION("One element")
	{
		char input[32] = "one";
		DynamicArray *vec = split_string(input, ' ');

		REQUIRE( DA_size(vec) == 1 );
		REQUIRE( std::string( DA_GET(vec, char*, 0 ) )  == std::string("one") );

		DA_free(vec);
	}

	SECTION("Some elements")
	{
		char input[32] = "one two three";
		DynamicArray *vec = split_string(input, ' ');

		REQUIRE( DA_size(vec) == 3 );
		REQUIRE( std::string( DA_GET(vec, char*, 0 ) )  == std::string("one") );
		REQUIRE( std::string( DA_GET(vec, char*, 1 ) )  == std::string("two") );
		REQUIRE( std::string( DA_GET(vec, char*, 2 ) )  == std::string("three") );

		DA_free(vec);
	}
}