#include <DynamicArray.h>
#include "catch2/catch.hpp"
#include <string.h>


TEST_CASE( "Test Dynamic Array add and get" )
{
	
	SECTION( "Add int" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_INT );

		int value = 15;

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_get_i(array, 0) == value );

		DA_free( array );
	}

	SECTION( "Add char" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_CHAR );

		char value = 55;

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_get_c(array, 0) == value );

		DA_free( array );
	}

	SECTION( "Add float" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_FLOAT );

		float value = 15;

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_get_f(array, 0) == value );

		DA_free( array );
	}

	SECTION( "Add long" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_LONG );

		long value = 15;

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_get_l(array, 0) == value );

		DA_free( array );
	}

	SECTION( "Add double" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_DOUBLE );

		double value = 15;

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_get_d(array, 0) == value );

		DA_free( array );
	}

	SECTION( "Add Pointer" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_POINTER );

		const char* value = "Test";

		DA_add( array, value );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( DA_GET(array, char*, 0) == value );

		DA_free( array );
	}

	SECTION( "Add costume" )
	{
		DynamicArray *array;
		typedef struct CostumType
		{
			int a;
			float b;
			char c[16];
		} CostumType;
		
		CostumType type;
		memset( &type, 0, sizeof(CostumType) );

		type.a = 1;
		type.b = 3.4;
		strcpy( type.c, "hallo" );

		array = DA_Init_Custom( sizeof(CostumType) );

		DA_add( array, &type );

		REQUIRE( DA_size(array) == 1 );

		REQUIRE( DA_capacity(array) == 16 );

		REQUIRE( memcmp( DA_get(array, 0), &type, sizeof(CostumType)) == 0 );

		DA_free( array );
	}

	SECTION( "Add more than 16 char Elements - to test realloc" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_CHAR );

		char value = 55;

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_size(array) == cnt );
			DA_add( array, value );
		}
		REQUIRE( DA_capacity( array ) == 32 );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_get_c(array, cnt ) == value );
		}

		DA_free( array );
	}

	SECTION( "Add more than 16 long Elements - to test realloc" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_LONG );

		long value = 55;

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_size(array) == cnt );
			DA_add( array, value );
		}
		REQUIRE( DA_capacity( array ) == 32 );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_get_l(array, cnt ) == value );
		}

		DA_free( array );
	}

	SECTION( "Add more than 16 pointer Elements - to test realloc" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_POINTER );

		const char* values[] = 
		{
			"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
			"11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
			"21", "22", "23", "24", "25", "26", "27", "28", "29", "30",
			"31", "32", "33", "34", "35", "36", "37", "38", "39", "40"
		};

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_size(array) == cnt );
			DA_add( array, values[cnt] );
		}
		REQUIRE( DA_capacity( array ) == 32 );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_GET(array, char*, cnt ) == values[cnt] );
		}

		DA_free( array );
	}

	SECTION( "Add more than 16 Costum Elements - to test realloc" )
	{
		DynamicArray *array;
		typedef struct CostumType
		{
			int a;
			float b;
			char c[16];
		} CostumType;
		
		CostumType type;
		memset( &type, 0, sizeof(CostumType) );

		type.a = 1;
		type.b = 3.4;
		strcpy( type.c, "hallo" );

		array = DA_Init_Custom( sizeof(CostumType) );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			type.a = cnt;
			REQUIRE( DA_size(array) == cnt );
			DA_add( array, &type );
		}
		REQUIRE( DA_capacity( array ) == 32 );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			type.a = cnt;
			REQUIRE( memcmp( DA_get(array, cnt), &type, sizeof(CostumType)) == 0 );
		}

		DA_free( array );
	}
}

TEST_CASE( "Test pop_back" )
{
	SECTION( "Add more than 16 long elements and pop_back them" )
	{
		DynamicArray *array;
		array = DA_Init( TYPE_LONG );

		for( int cnt = 0; cnt < 32; cnt++ )
		{
			REQUIRE( DA_size(array) == cnt );
			DA_add( array, (long)cnt );
			REQUIRE( DA_BACK( array, long ) == cnt );
		}
		REQUIRE( DA_capacity( array ) == 32 );

		for( int cnt = 32; cnt > 0; cnt-- )
		{
			REQUIRE( DA_size( array ) == cnt );
			REQUIRE( DA_POP_BACK( array, long ) == (long) cnt -1 );
		}

		DA_free( array );
	}
}