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
	{ "pointer", sizeof(void*) },
	{"costum", 0 }
};

void DA_grow_if_necessary(  DynamicArray *array );

void DA_clear( DynamicArray *array )
{
	array->size = 0;
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
	free( array->pBuffer );
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

	DA_grow_if_necessary( array );

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
		case TYPE_POINTER:
			((void**)array->pBuffer)[array->size++] = va_arg( valist, void* );
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

void DA_add_range( DynamicArray *array, size_t number, ... )
{
	va_list valist;
	char* pszValue;
	int* piValue;
	float* pfValue;
	long* plValue;
	double* pdValue;
	void** ppValue;
	char** ppszValue;
	size_t cnt;

	va_start( valist, number );

	switch (array->type )
	{
		case TYPE_CHAR:
			pszValue = va_arg( valist, char* );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((char*)array->pBuffer)[array->size++] = pszValue[cnt];
			}
			break;
		case TYPE_INT:
			piValue = va_arg( valist, int* );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((int*)array->pBuffer)[array->size++] = piValue[cnt];
			}
			break;
		case TYPE_FLOAT:
			pfValue = va_arg( valist, float* );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((float*)array->pBuffer)[array->size++] = pfValue[cnt];
			}
			break;
		case TYPE_LONG:
			plValue = va_arg( valist, long* );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((long*)array->pBuffer)[array->size++] = plValue[cnt];
			}
			break;
		case TYPE_DOUBLE:
			pdValue = va_arg( valist, double* );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((double*)array->pBuffer)[array->size++] = pdValue[cnt];
			}
			break;
		case TYPE_POINTER:
			ppValue = va_arg( valist, void** );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				((void**)array->pBuffer)[array->size++] = ppValue[cnt];
			}
			break;
		case TYPE_COSTUM:
			ppszValue = va_arg( valist, char** );
			for( cnt = 0; cnt < number; cnt++ )
			{
				DA_grow_if_necessary( array );
				memcpy( ((char*)array->pBuffer) + array->size * tInfo[TYPE_COSTUM].size, ppszValue[cnt], tInfo[TYPE_COSTUM].size );
				array->size++;
			}
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

void* DA_pop_back( DynamicArray *array )
{
	if( array->size == 0 ) return NULL;

	array->size--;

	return ((char*)array->pBuffer) + tInfo[array->type].size * array->size;
}

void* DA_back( DynamicArray *array )
{
	return ((char*)array->pBuffer) + tInfo[array->type].size * (array->size - 1);
}

void DA_grow_if_necessary(  DynamicArray *array )
{
	if( array->size >= array->capacity )
	{
		array->capacity *= 2;
		array->pBuffer = realloc( array->pBuffer, array->capacity * tInfo[array->type].size );
	}
}