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
}
