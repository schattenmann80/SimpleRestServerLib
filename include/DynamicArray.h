#ifndef DYNAMIC_ARRAY
#define DYNAMIC_ARRAY

#include <stdlib.h>
#include <stdarg.h>

#define TYPE_CHAR 0
#define TYPE_INT 1
#define TYPE_FLOAT 2
#define TYPE_LONG 3
#define TYPE_DOUBLE 4
#define TYPE_COSTUM 5

#define DA_GET( a, t, i ) *((t*)DA_get( a, i ))
#define DA_POP_BACK( a, t ) *((t*)DA_pop_back( a ))
#define DA_BACK( a, t ) *((t*)DA_back( a ))

typedef struct DynamicArray DynamicArray;

extern void DA_clear( DynamicArray *array );

extern DynamicArray *DA_Init( int type );
extern DynamicArray *DA_Init_Custom( size_t size );
extern void DA_free( DynamicArray *array );

extern size_t DA_size( DynamicArray *array );
extern size_t DA_capacity( DynamicArray *array );

extern void DA_add( DynamicArray *array, ... );

extern void* DA_get( DynamicArray *array, size_t index );
extern char DA_get_c( DynamicArray *array, size_t index );
extern int DA_get_i( DynamicArray *array, size_t index );
extern float DA_get_f( DynamicArray *array, size_t index );
extern long DA_get_l( DynamicArray *array, size_t index );
extern double DA_get_d( DynamicArray *array, size_t index );
extern char* DA_get_cp( DynamicArray *array, size_t index );

extern void* DA_pop_back( DynamicArray *array );

extern void* DA_back( DynamicArray *array );

#endif