#include <DynamicArray.h>
#include <string.h>

typedef struct DynamicArray
{
	size_t size;
	size_t capacity;

	int type;

	void* pBuffer;
} DynamicArray;


typedef struct
{
	const char* name;
	size_t size;
} TypeInfo;


TypeInfo tInfo[] =
{
	{"char", sizeof(char) },
	{"int", sizeof(int) },
	{"float", sizeof(float) },
	{"long", sizeof(long) },
	{"double", sizeof(double) },
	{"costum", 0 }
};


void DA_clear( DynamicArray *array )
{
	free( array->pBuffer );

	array->capacity = 16;

	array->size = 0;

	array->pBuffer = malloc( array->capacity * tInfo[array->type].size );
}

DynamicArray *DA_Init( int type )
{
	DynamicArray *array = (DynamicArray *) malloc( sizeof(DynamicArray) );
	memset( array, 0, sizeof( DynamicArray ) );

	array->type = type;

	array->capacity = 16;

	array->pBuffer = malloc( array->capacity * tInfo[type].size );

	return array;
}

DynamicArray *DA_Init_Custom( size_t size )
{
	DynamicArray *array = (DynamicArray *) malloc( sizeof(DynamicArray) );
	memset( array, 0, sizeof( DynamicArray ) );

	array->type = TYPE_COSTUM;

	tInfo[TYPE_COSTUM].size = size;

	array->capacity = 16;

	array->pBuffer = malloc( array->capacity * tInfo[TYPE_COSTUM].size );

	return array;
}

void DA_free( DynamicArray *array )
{
	free( array );
}

size_t DA_size( DynamicArray *array )
{
	return array->size;
}

size_t DA_capacity( DynamicArray *array )
{
	return array->capacity;
}

void DA_add( DynamicArray *array, ... )
{
	va_list valist;

	va_start( valist, array );

	if( array->size >= array->capacity )
	{
		array->capacity *= 2;
		array->pBuffer = realloc( array->pBuffer, array->capacity * tInfo[array->type].size );
	}

	switch (array->type )
	{
	case TYPE_CHAR:
		((char*)array->pBuffer)[array->size++] = (char) va_arg( valist, int );
		break;
	case TYPE_INT:
		((int*)array->pBuffer)[array->size++] = va_arg( valist, int );
		break;
	case TYPE_FLOAT:
		((float*)array->pBuffer)[array->size++] = (float) va_arg( valist, double );
		break;
	case TYPE_LONG:
		((long*)array->pBuffer)[array->size++] = va_arg( valist, long );
		break;
	case TYPE_DOUBLE:
		((double*)array->pBuffer)[array->size++] = va_arg( valist, double );
		break;
	case TYPE_COSTUM:
		memcpy( ((char*)array->pBuffer) + array->size * tInfo[TYPE_COSTUM].size, va_arg( valist, char* ), tInfo[TYPE_COSTUM].size );
		array->size++;
		break;
	
	default:
		break;
	}

	va_end(valist);
}

void* DA_get( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return NULL;

	return ((char*)array->pBuffer) + index * tInfo[array->type].size;
}

char DA_get_c( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return 0;

	return ((char*)array->pBuffer)[index];
}

int DA_get_i( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return 0;

	return ((int*)array->pBuffer)[index];
}

float DA_get_f( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return 0;

	return ((float*)array->pBuffer)[index];
}

long DA_get_l( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return 0;

	return ((long*)array->pBuffer)[index];
}

double DA_get_d( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return 0;

	return ((double*)array->pBuffer)[index];
}

char* DA_get_cp( DynamicArray *array, size_t index )
{
	if( array->size <= index ) return NULL;

	return ((char*)array->pBuffer) + index;
}

extern void* DA_pop_back( DynamicArray *array )
{
	if( array->size == 0 ) return NULL;

	array->size--;

	return ((char*)array->pBuffer) + tInfo[array->type].size * array->size;
}

extern void* DA_back( DynamicArray *array )
{
	return ((char*)array->pBuffer) + tInfo[array->type].size * (array->size - 1);
}