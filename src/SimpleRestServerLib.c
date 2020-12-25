#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "SimpleRestServerLib.h"
#include "DynamicArray.h"

typedef struct RSL_ResponceDefinition
{
	RSL_ResponceFunction *pResponeFunctions;
	char szRequestMethod[32];
	char *pszUrl;
}RSL_ResponceDefinition;

typedef struct RSL_RestServer
{
	// Options
	int iPort;
	int bHTTPS;
	char* pszCertificatFilePath;
	char* pszCertificatKeyFilePath;
	int iTimeoutSec;
	int iTimeoutMiliSec;
	int bVerbose;

	RSL_ErrorFunction *pErrorFunction;
	DynamicArray *pResponeDefs;

	// Internals
	int iFileDescriptorServer;
	int bRunning;
	SSL_CTX *ctx;
} RSL_RestServer;

typedef struct RSL_ClientData
{
	int iFileDescriptorClient;
	SSL *ssl;

	DynamicArray *pRequestString;

	const char* pszResponce;
} RSL_ClientData;

const char *pszVerboseMessageList[] =
{
	"",
	"No data to parse!",
	"The header dosn't contain a valid request method!",
	"Header is not parsable!",
	"No url to parse!",
	"= and & count dosn't match!",
	"No responce function found!"
};

static void myopenssl_create_context( RSL_RestServer *pRestServer );
static int default_error_function( const char* pszErrorMessage, int bIsOpenSSL );
static int acept_client( RSL_RestServer *pRestServer );
static int create_socket( RSL_RestServer *pRestServer );
static void init_openssl();
static void myopenssl_configure_context( RSL_RestServer *pRestServer );
static int check_for_data_to_read_timeout( RSL_RestServer *pRestServer, int file_descriptor, int sec, int milisec );
static int check_for_data_to_read( RSL_RestServer *pRestServer, int file_descriptor );
static int read_data_and_check_if_there_is_more( RSL_RestServer *pRestServer, RSL_ClientData *pClientData );
static void receive_data( RSL_RestServer *pRestServer, RSL_ClientData *pClientData );
		
static void create_responce( RSL_RestServer *pRestServer, RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest );
static const char* error_responce( RSL_RestServer *pRestServer, RSL_ClientData *pClientData );

static void free_client_data( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest );
static void free_ClientData( RSL_ClientData *pClientData );
static void free_ClientRequest( RSL_ClientRequest *pClientRequest );

static char* skip_whitespace( char* pData );
static DynamicArray * split_http_request( char* pszClientData );
static int parse_http_request( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest );
static int parse_url_arguments( RSL_ClientRequest *pClientRequest );
static void verbose_output( RSL_RestServer *pRestServer, int iMessageId );

static DynamicArray* split_string( char * szData, char delimiter );

/************************* Public functions: *************************/
/***********************************************************************/


RSL_RestServer* rsl_new_rest_server()
{
	RSL_RestServer *pRestServer;

	pRestServer = (RSL_RestServer*) calloc( 1, sizeof( RSL_RestServer ) );

	pRestServer->pErrorFunction = default_error_function;

	pRestServer->pResponeDefs = DA_Init_Custom( sizeof(RSL_ResponceDefinition));

	pRestServer->iTimeoutSec = 5;

	return pRestServer;
}

void rsl_clean_and_free_rest_server( RSL_RestServer *pRestServer )
{
	if( pRestServer->pszCertificatFilePath != NULL ) 
	{
		free( pRestServer->pszCertificatFilePath );
	}
	if( pRestServer->pszCertificatKeyFilePath != NULL )
	{
		free( pRestServer->pszCertificatKeyFilePath );
	}

	close( pRestServer->iFileDescriptorServer );

	if( pRestServer->bHTTPS )
	{
		SSL_CTX_free( pRestServer->ctx );
	}

	for( size_t cnt = 0; cnt < DA_size( pRestServer->pResponeDefs ); cnt++ )
	{
		if( DA_GET_POINTER( pRestServer->pResponeDefs, RSL_ResponceDefinition, cnt)->pszUrl != NULL )
		{
			free( DA_GET_POINTER( pRestServer->pResponeDefs, RSL_ResponceDefinition, cnt)->pszUrl );
		}
		DA_free( pRestServer->pResponeDefs );
	}

	free( pRestServer );
}

int rsl_option_set_port( RSL_RestServer *pRestServer, int iPort )
{
	if( pRestServer->bRunning ) return 0;

	pRestServer->iPort = iPort;

	return 1;
}

int rsl_option_set_HTTPS( RSL_RestServer *pRestServer, int bHTTPSOn )
{
	if( pRestServer->bRunning ) return 0;

	pRestServer->bHTTPS = bHTTPSOn;

	return 1;
}

int rsl_option_set_certificate_file_path( RSL_RestServer *pRestServer, const char * pszPath )
{
	if( pRestServer->bRunning || pszPath == NULL ) return 0;

	if( pRestServer->pszCertificatFilePath != NULL ) 
	{
		free( pRestServer->pszCertificatFilePath );
	}

	pRestServer->pszCertificatFilePath = strdup( pszPath );

	return 1;
}

int rsl_option_set_certificate_key_file_path( RSL_RestServer *pRestServer, const char * pszPath )
{
	if( pRestServer->bRunning || pszPath == NULL ) return 0;

	if( pRestServer->pszCertificatKeyFilePath != NULL ) 
	{
		free( pRestServer->pszCertificatKeyFilePath );
	}

	pRestServer->pszCertificatKeyFilePath = strdup( pszPath );

	return 1;
}

int rsl_option_set_Timeout( RSL_RestServer *pRestServer, int iSec, int iMiliSec )
{
	pRestServer->iTimeoutSec = iSec;
	pRestServer->iTimeoutMiliSec = iMiliSec;

	return 1;
}

int rsl_option_set_error_function( RSL_RestServer *pRestServer, RSL_ErrorFunction *pErrorFunction )
{
	pRestServer->pErrorFunction = pErrorFunction;
	return 1;
}

int rsl_option_add_responce_function( RSL_RestServer *pRestServer, 
											RSL_ResponceFunction pResponceFunction, 
											const char* pszUrl,
											const char* szRequestMethod )
{
	RSL_ResponceDefinition def;
	def.pResponeFunctions = pResponceFunction;
	def.pszUrl = strdup( pszUrl );
	strncpy( def.szRequestMethod, szRequestMethod, sizeof def.szRequestMethod -1 );

	DA_add( pRestServer->pResponeDefs, &def );

	return 1;
}

int rsl_option_set_verbose( RSL_RestServer *pRestServer, int bVerbose )
{
	pRestServer->bVerbose = bVerbose;
	return 1;
}

void rsl_run( RSL_RestServer *pRestServer )
{
	if( pRestServer->bRunning == 0 )
	{
		create_socket( pRestServer );

		if( pRestServer->bHTTPS )
		{
			init_openssl();
			myopenssl_create_context( pRestServer );
			myopenssl_configure_context( pRestServer );
		}
	}

	pRestServer->bRunning = 1;

	while( 1 )
	{
		int iRetVal = 0;
		RSL_ClientData sClientData;
		RSL_ClientRequest sClientRequest;

		memset( &sClientData, 0, sizeof(RSL_ClientData) );
		memset( &sClientRequest, 0, sizeof(RSL_ClientRequest) );
		
		sClientData.iFileDescriptorClient = acept_client( pRestServer );

		if( pRestServer->bHTTPS )
		{
			sClientData.ssl = SSL_new( pRestServer->ctx );
			SSL_set_fd( sClientData.ssl, sClientData.iFileDescriptorClient);
		}

		receive_data( pRestServer, &sClientData );

		iRetVal = parse_http_request( &sClientData, &sClientRequest );
		if( iRetVal != 1 ) verbose_output( pRestServer, -iRetVal );

		iRetVal = parse_url_arguments( &sClientRequest );
		if( iRetVal != 1 ) verbose_output( pRestServer, -iRetVal );

		create_responce( pRestServer, &sClientData, &sClientRequest );

		if( pRestServer->bHTTPS )
		{
			SSL_write( sClientData.ssl, sClientData.pszResponce, strlen( sClientData.pszResponce ) );
		}
		else
		{
			write( sClientData.iFileDescriptorClient, sClientData.pszResponce, strlen( sClientData.pszResponce ) );
		}
		
		free_client_data( &sClientData, &sClientRequest );
		close( sClientData.iFileDescriptorClient );
	}
}


/*************************  Interal functions: *************************/
/***********************************************************************/


/***************** Function for communication ******************/
static void myopenssl_create_context( RSL_RestServer *pRestServer )
{
	const SSL_METHOD *method;

	method = SSLv23_server_method();

	pRestServer->ctx = SSL_CTX_new(method);
	if ( !pRestServer->ctx ) {
		if( pRestServer->pErrorFunction("Unable to create SSL context", 1 ) )
		{
			exit(EXIT_FAILURE);
		}
	}
}

static int default_error_function( const char* pszErrorMessage, int bIsOpenSSL )
{
	if( bIsOpenSSL )
	{
		ERR_print_errors_fp(stderr);
	}

	if( pszErrorMessage != NULL ) perror(pszErrorMessage);
	
	return 1;
}

static int acept_client( RSL_RestServer *pRestServer )
{
	struct sockaddr_in addr;
	uint len = sizeof(addr);

	int ifileDescriptorClient = accept( pRestServer->iFileDescriptorServer, (struct sockaddr*) &addr, &len );

	if ( ifileDescriptorClient < 0 ) {
		if( pRestServer->pErrorFunction("Unable to accept", 0 ) )
		{
			exit(EXIT_FAILURE);
		}
	}

	return ifileDescriptorClient;
}	

static int create_socket( RSL_RestServer *pRestServer )
{
	struct sockaddr_in addr;
	int enable = 1;

	addr.sin_family = AF_INET;
	addr.sin_port = htons( pRestServer->iPort );
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	pRestServer->iFileDescriptorServer = socket( AF_INET, SOCK_STREAM, 0 );
	if( pRestServer->iFileDescriptorServer < 0 ) {
		if( pRestServer->pErrorFunction("Unable to create socket", 0 ) )
		{
			exit(EXIT_FAILURE);
		} 
	}

	
	if (setsockopt(pRestServer->iFileDescriptorServer, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		if( pRestServer->pErrorFunction("setsockopt(SO_REUSEADDR) failed", 0 ) )
		{
			exit(EXIT_FAILURE);
		}
	}

	if( bind( pRestServer->iFileDescriptorServer, (struct sockaddr*)&addr, sizeof(addr) ) < 0 ) {
		if( pRestServer->pErrorFunction("Unable to bind", 0 ) )
		{
			exit(EXIT_FAILURE);
		}
	}

	if( listen(pRestServer->iFileDescriptorServer, 1) < 0 ) {
		if( pRestServer->pErrorFunction("Unable to listen", 0 ) )
		{
			exit(EXIT_FAILURE);
		}
	}

	return 1;
}

static void init_openssl()
{ 
	SSL_load_error_strings();	
	OpenSSL_add_ssl_algorithms();
}

static void myopenssl_configure_context( RSL_RestServer *pRestServer )
{
	const char* pszCertificatePath = "cert.pem";
	const char* pszCertificateKeyPath = "key.pem";

	if( pRestServer->pszCertificatFilePath != NULL )
	{
		pszCertificatePath = pRestServer->pszCertificatFilePath;
	}

	if( pRestServer->pszCertificatKeyFilePath != NULL )
	{
		pszCertificateKeyPath = pRestServer->pszCertificatKeyFilePath;
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file( pRestServer->ctx, pszCertificatePath, SSL_FILETYPE_PEM) <= 0) {
		if( pRestServer->pErrorFunction( NULL, 1 ))
		{
			exit(EXIT_FAILURE);
		}
	}

	if (SSL_CTX_use_PrivateKey_file( pRestServer->ctx, pszCertificateKeyPath, SSL_FILETYPE_PEM) <= 0 ) {
		if( pRestServer->pErrorFunction( NULL, 1 ))
		{
			exit(EXIT_FAILURE);
		}
	}
}

static int check_for_data_to_read_timeout( RSL_RestServer *pRestServer, int iFileDescriptor, int sec, int milisec )
{
	fd_set fds;
	struct timeval tv;
	int retval;

	FD_ZERO( &fds );
	FD_SET( iFileDescriptor, &fds );

	tv.tv_sec = sec;
	tv.tv_usec = milisec;

	retval = select( FD_SETSIZE, &fds, NULL, NULL, &tv );

	if( retval == -1 )
	{
		pRestServer->pErrorFunction( "select()", 0 );
	}
	return retval;
}

static int check_for_data_to_read( RSL_RestServer *pRestServer, int file_descriptor )
{
	return check_for_data_to_read_timeout( pRestServer,
		file_descriptor, pRestServer->iTimeoutSec, pRestServer->iTimeoutMiliSec );
}

static int read_data_and_check_if_there_is_more( RSL_RestServer *pRestServer, RSL_ClientData *pClientData )
{
	int iReadRetVal = 0;
	char buffer[512];

	memset( buffer, 0, sizeof buffer );

	if( pRestServer->bHTTPS )
	{
		iReadRetVal = SSL_read( pClientData->ssl, buffer, sizeof buffer -1 );
	}
	else
	{
		iReadRetVal = read( pClientData->iFileDescriptorClient, buffer, sizeof buffer -1 );
	}
	
	if( iReadRetVal <= 0 )
	{
		pRestServer->pErrorFunction("(SSL_)read returned error", pRestServer->bHTTPS );
		return 0;
	}

	DA_add_range( pClientData->pRequestString, strlen( buffer ), buffer );

	return check_for_data_to_read_timeout( pRestServer, pClientData->iFileDescriptorClient, 0, 100 )
		|| ( pRestServer->bHTTPS && SSL_pending( pClientData->ssl ) > 0 );
}


static void receive_data( RSL_RestServer *pRestServer, RSL_ClientData *pClientData )
{

	if( pRestServer->bHTTPS && SSL_accept( pClientData->ssl ) <= 0 ) {
		pRestServer->pErrorFunction( NULL, 1 );
		return;
	}


	if( check_for_data_to_read( pRestServer, pClientData->iFileDescriptorClient ) == 0 
		|| ( pRestServer->bHTTPS && SSL_pending( pClientData->ssl ) > 0 ) )
	{
		pRestServer->pErrorFunction("No response from client", HTTP );
		return;
	}

	pClientData->pRequestString = DA_Init(TYPE_CHAR);

	while( read_data_and_check_if_there_is_more( pRestServer, pClientData ) )
	{
		
	}
	DA_add( pClientData->pRequestString, '\0' );

	if( pRestServer->bVerbose )
	{
		puts( DA_get_cp( pClientData->pRequestString, 0 ) );
	}
}

/***************** Function to create response ******************/
static void create_responce( RSL_RestServer *pRestServer, RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest )
{
	int cnt;

	for( cnt = 0; cnt < DA_size( pRestServer->pResponeDefs); cnt++ )
	{
		RSL_ResponceDefinition *def = (RSL_ResponceDefinition*)DA_get( pRestServer->pResponeDefs, cnt );
		if( strcmp(def->szRequestMethod, pClientRequest->pszRequestMethod ) == 0
			&& strcmp( def->pszUrl, pClientRequest->pszUrl ) == 0 )
		{
			pClientData->pszResponce = def->pResponeFunctions( pRestServer, pClientRequest );
			break;
		}
	}
	
	if( cnt == DA_size( pRestServer->pResponeDefs) || pClientData->pszResponce == NULL )
	{
		pClientData->pszResponce = error_responce( pRestServer, pClientData );
		verbose_output( pRestServer, 6 );
	}
}

static const char* error_responce( RSL_RestServer *pRestServer, RSL_ClientData *pClientData )
{
	static const char *responce = "HTTP/1.1 404 Not Found\r\n\r\n";

	return responce;
}


/***************** Functions to clean menory ******************/
static void free_client_data( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest )
{
	free_ClientData( pClientData );
	free_ClientRequest( pClientRequest );
}

static void free_ClientData( RSL_ClientData *pClientData )
{
	DA_free( pClientData->pRequestString );
	pClientData->pRequestString = NULL;

	if( pClientData->ssl != NULL )
	{
		SSL_shutdown( pClientData->ssl );
		SSL_free( pClientData->ssl );
	}
}

static void free_ClientRequest( RSL_ClientRequest *pClientRequest )
{
	if( pClientRequest->pArguments != NULL )
	{
		free( pClientRequest->pArguments );
	}
}

/***************** Function to process data ******************/
static char* skip_whitespace( char* pData )
{
	while( pData && *pData && *pData <= ' ' )
	{
		pData++;
	}
	return pData;
}

static DynamicArray * split_http_request( char* pszClientData )
{
	char *pszIndex;
	char *pszStart;
	char *pszBodyStart;
	DynamicArray *vecTokens;

	if( pszClientData == NULL || *pszClientData == '\0' ) return NULL;

	pszIndex = pszClientData;

	vecTokens = DA_Init( TYPE_POINTER );

	//Find Start of the Body
	if( ( pszBodyStart = strstr( pszIndex, "\n\n")) == NULL )
	{
		if( ( pszBodyStart = strstr( pszIndex, "\r\n\r\n") ) == NULL )
		{
			// No body found
			DA_free( vecTokens );
			return NULL;
		}
		else {
			*pszBodyStart = '\0';
			pszBodyStart += 4;
		}
	} else {
		*pszBodyStart = '\0';
		pszBodyStart += 2;
	}

	for( pszStart = pszIndex; pszIndex < pszBodyStart && DA_size( vecTokens ) < 3; pszIndex++ )
	{
		if( *pszIndex == ' ' || *pszIndex == '\n' || *pszIndex == '\r' )
		{
			if( pszStart != pszIndex )
			{
				*pszIndex = '\0'; // Replace whitespace with NULL;
				DA_add( vecTokens, pszStart );
			}
			pszStart = pszIndex + 1; // Skip whitespace/Null
		}
	}

	pszStart = skip_whitespace(pszStart);
	if( *pszStart != '\0' ){
		DA_add( vecTokens, skip_whitespace(pszStart) );
	}

	DA_add( vecTokens, pszBodyStart );
	return vecTokens;
}

static int parse_http_request( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest )
{

	DynamicArray *vecTokens;
	const char** pList;
	const char *ppRequestMethods[] =
	{
		"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS", "CONNECT", NULL
	};

	//if( pClientData->pszRequestBuffer == NULL )	return -1;
	if( DA_size( pClientData->pRequestString ) == 0 )	return -1;

	vecTokens = split_http_request( DA_get_cp( pClientData->pRequestString, 0 ) );

	// vecTokens must include request method, url, http version and body
	if( DA_size( vecTokens) < 4 ) {
		DA_free( vecTokens );
		return -1;
	}

	for( pList = ppRequestMethods; *pList != NULL; pList++ )
	{
		if( strncmp( DA_GET( vecTokens, char*, 0 ), *pList, strlen( *pList ) ) == 0 )
		{
			strcpy( pClientRequest->pszRequestMethod, *pList );
			break;
		}
	}
	if( *pClientRequest->pszRequestMethod == '\0' ) {
		DA_free( vecTokens );
		return -2;
	}

	pClientRequest->pszUrl = DA_GET( vecTokens, char*, 1 );

	pClientRequest->pszHttpVerison = DA_GET( vecTokens, char*, 2 );

	pClientRequest->pszBody = DA_BACK( vecTokens, char* );

	if( DA_size( vecTokens ) > 4 )
	{
		pClientRequest->pszHeaderArguments = DA_GET( vecTokens, char*, 3 );
	}

	DA_free( vecTokens );
	return 1;
}

static int parse_url_arguments( RSL_ClientRequest *pClientRequest )
{
	char* pszQuestionMark = NULL;
	char* pszDataStart;
	int cnt;
	char* pItem;
	int iCntEqualChars = 0;

	if( pClientRequest->pszUrl == NULL ) return -4;

	pszQuestionMark = strchr( pClientRequest->pszUrl, '?' );

	if( pszQuestionMark == NULL ) return 1;

	*pszQuestionMark = '\0';

	pszDataStart = pszQuestionMark + 1;

	DynamicArray *vecArgPairs = split_string( pszDataStart, '&' );

	if( vecArgPairs == NULL ) return -5;

	pClientRequest->iArgumentCount = DA_size( vecArgPairs );

	pClientRequest->pArguments = (RSL_URLArgument*) calloc( pClientRequest->iArgumentCount, sizeof(RSL_URLArgument) );

	for( size_t cnt = 0; cnt < DA_size( vecArgPairs ); cnt++ )
	{
		pClientRequest->pArguments[cnt].pszKey = DA_GET( vecArgPairs, char*, cnt );
		if( ( pszDataStart = strchr( DA_GET( vecArgPairs, char*, cnt ), '=')) != NULL )
		{
			*pszDataStart = '\0';
			pClientRequest->pArguments[cnt].pszValue = pszDataStart + 1;
		}
	}

	DA_free( vecArgPairs );

	return 1;
}

static void verbose_output( RSL_RestServer *pRestServer, int iMessageId )
{
	if( pRestServer->bVerbose == 0 ) return;

	printf( "VERBOSE:: %s\n", pszVerboseMessageList[iMessageId] );
}

static DynamicArray* split_string( char * szData, char delimiter )
{
	DynamicArray *vec = DA_Init( TYPE_POINTER );

	char* pStart;

	for( pStart = szData; szData && *szData; szData++ )
	{
		if( *szData == delimiter )
		{
			if( szData != pStart ) DA_add( vec, pStart );
			*szData = '\0';
			pStart = szData + 1;
		}
	}

	if( pStart != szData ) DA_add( vec, pStart );
	
	if( DA_size( vec ) > 0 ) return vec;

	DA_free(vec);
	return NULL;
}