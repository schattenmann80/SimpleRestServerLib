#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../include/SimpleRestServerLib.h"

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

	RSL_ErrorFunction *pErrorFunction;
	RSL_ResponceDefinition **ppResponceDefs;
	size_t iResponceDefsCount;
	size_t iResponceDefsCapacity;

	// Internals
	int iFileDescriptorServer;
	int bRunning;
	SSL_CTX *ctx;
} RSL_RestServer;

typedef struct RSL_ClientData
{
	int iFileDescriptorClient;
	SSL *ssl;

	char* pszRequestBuffer;
	size_t iRequestCapacity;
	size_t iRequestSize;

	const char* pszResponce;
} RSL_ClientData;

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
static int parse_http_request( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest );
static void parse_url_arguments( RSL_ClientRequest *pClientRequest );


/************************* Public functions: *************************/
/***********************************************************************/


RSL_RestServer* rsl_new_rest_server()
{
	RSL_RestServer *pRestServer;

	pRestServer = (RSL_RestServer*) calloc( 1, sizeof( RSL_RestServer ) );

	pRestServer->pErrorFunction = default_error_function;

	pRestServer->ppResponceDefs = ( RSL_ResponceDefinition**) calloc( 16, sizeof( RSL_ResponceDefinition*) );
	pRestServer->iResponceDefsCapacity = 16;
	pRestServer->iResponceDefsCount = 0;

	pRestServer->iTimeoutSec = 5;

	return pRestServer;
}

void rsl_clean_and_free_rest_server( RSL_RestServer *pRestServer )
{
	int cnt;
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

	if( pRestServer->iResponceDefsCount > 0 )
	{
		for( cnt = 0; cnt < pRestServer->iResponceDefsCount; cnt++ )
		{
			if( pRestServer->ppResponceDefs[cnt]->pszUrl != NULL )
			{
				free( pRestServer->ppResponceDefs[cnt]->pszUrl );
			}
			free( pRestServer->ppResponceDefs[cnt] );
		}
		free( pRestServer->ppResponceDefs );
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
	if( pRestServer->iResponceDefsCapacity <= pRestServer->iResponceDefsCount )
	{
		pRestServer->iResponceDefsCapacity += 16;
		pRestServer->ppResponceDefs = (RSL_ResponceDefinition**) realloc( pRestServer->ppResponceDefs,
					pRestServer->iResponceDefsCapacity * sizeof( RSL_ResponceDefinition*)  );

		if( pRestServer->ppResponceDefs == NULL )
		{
			pRestServer->pErrorFunction("realloc error", 0 );
		}
	}

	RSL_ResponceDefinition * pResDef = (RSL_ResponceDefinition*) calloc( 1, sizeof( RSL_ResponceDefinition) );
	if( pResDef == NULL )
	{
		pRestServer->pErrorFunction("calloc error", 0 );
	}
	pResDef->pResponeFunctions = pResponceFunction;
	pResDef->pszUrl = strdup( pszUrl );
	strncpy( pResDef->szRequestMethod, szRequestMethod, sizeof pResDef->szRequestMethod -1 );

	pRestServer->ppResponceDefs[pRestServer->iResponceDefsCount] = pResDef;
	pRestServer->iResponceDefsCount++;

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

		parse_http_request( &sClientData, &sClientRequest );
		parse_url_arguments( &sClientRequest );

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

	if( pRestServer->bHTTPS )
	{
		iReadRetVal = SSL_read( pClientData->ssl, 
				pClientData->pszRequestBuffer + pClientData->iRequestSize, 
				pClientData->iRequestCapacity - pClientData->iRequestSize -1 );
	}
	else
	{
		iReadRetVal = read( pClientData->iFileDescriptorClient,
							pClientData->pszRequestBuffer + pClientData->iRequestSize, 
							pClientData->iRequestCapacity - pClientData->iRequestSize -1 );
	}
	
	if( iReadRetVal <= 0 )
	{
		pRestServer->pErrorFunction("(SSL_)read returned error", pRestServer->bHTTPS );
		return 0;
	}

	pClientData->iRequestSize += iReadRetVal;
	pClientData->pszRequestBuffer[ pClientData->iRequestSize ] = '\0';

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

	pClientData->iRequestCapacity = 1024;
	pClientData->iRequestSize = 0;

	pClientData->pszRequestBuffer = (char*) malloc( pClientData->iRequestCapacity );

	if( pClientData->pszRequestBuffer == NULL )
	{
		pRestServer->pErrorFunction("Error while mallocing", HTTP );
		return;
	}

	while( read_data_and_check_if_there_is_more( pRestServer, pClientData ) )
	{
		if( pClientData->iRequestSize >= pClientData->iRequestCapacity -1 )
		{
			pClientData->iRequestCapacity *= 2;
			pClientData->pszRequestBuffer = (char*) realloc( pClientData->pszRequestBuffer, pClientData->iRequestCapacity );

			if( pClientData->pszRequestBuffer == NULL )
			{
				pRestServer->pErrorFunction("Error during realloc", HTTP );
				return;
			}
		}
	}
}

/***************** Function to create response ******************/
static void create_responce( RSL_RestServer *pRestServer, RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest )
{
	int cnt;

	for( cnt = 0; cnt < pRestServer->iResponceDefsCount; cnt++ )
	{
		if( strcmp(pRestServer->ppResponceDefs[cnt]->szRequestMethod, pClientRequest->pszRequestMethod ) == 0
			&& strcmp( pRestServer->ppResponceDefs[cnt]->pszUrl, pClientRequest->pszUrl ) == 0 )
		{
			pClientData->pszResponce = pRestServer->ppResponceDefs[cnt]->pResponeFunctions( pRestServer, pClientRequest );
			break;
		}
	}
	
	if( cnt == pRestServer->iResponceDefsCount || pClientData->pszResponce == NULL )
	{
		pClientData->pszResponce = error_responce( pRestServer, pClientData );
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
	if( pClientData->pszRequestBuffer != NULL )
	{
		free( pClientData->pszRequestBuffer );
	}

	pClientData->iRequestCapacity = 0;
	pClientData->iRequestSize = 0;

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

static int parse_http_request( RSL_ClientData *pClientData, RSL_ClientRequest *pClientRequest )
{
	char *pDatStart;
	char* pDatEnd;
	const char** pList;
	const char *ppRequestMethods[] =
	{
		"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS", "CONNECT", NULL
	};

	if( pClientData->pszRequestBuffer == NULL ) return 0;

	pDatStart = pClientData->pszRequestBuffer;

	pDatStart = skip_whitespace( pDatStart );

	if( *pDatStart == '\0' ) return 0;

	for( pList = ppRequestMethods; *pList != NULL; pList++ )
	{
		if( strncmp( pDatStart, *pList, strlen( *pList ) ) == 0 )
		{
			strcpy( pClientRequest->pszRequestMethod, *pList );
			pDatStart += strlen( *pList );
			break;
		}
	}

	if( *pClientRequest->pszRequestMethod == '\0' ) return 0;

	pDatStart = skip_whitespace( pDatStart ); if( *pDatStart == '\0' ) return 0;

	for( pDatEnd = pDatStart; *pDatEnd != '\0' && *pDatEnd > ' '; pDatEnd++ );

	if( *pDatEnd == '\0' ) return 0;

	*pDatEnd = '\0';

	pClientRequest->pszUrl = pDatStart;

	for( pDatStart = pDatEnd + 1; *pDatStart != '\0'; pDatStart++ )
	{
		if( pDatStart[1] == '\0' &&  pDatStart[2] == '\0' && pDatStart[3] == '\0' ) return 0;

		if( strncmp( pDatStart, "\r\n\r\n", 4 ) == 0 )
		{
			pDatStart += 4;
			break;
		}

		if( strncmp( pDatStart, "\n\n", 2 ) == 0 )
		{
			pDatStart += 2;
		}
	}

	pClientRequest->pszBody = pDatStart;
	return 1;
}

static void parse_url_arguments( RSL_ClientRequest *pClientRequest )
{
	char* pszQuestionMark = NULL;
	char* pszDataStart;
	int cnt;
	char* pItem;
	int iCntEqualChars = 0;

	if( pClientRequest->pszUrl == NULL ) return;

	pszQuestionMark = strchr( pClientRequest->pszUrl, '?' );

	if( pszQuestionMark == NULL ) return;

	*pszQuestionMark = '\0';

	pszDataStart = pszQuestionMark + 1;

	
	pClientRequest->iArgumentCount = 0;
	for( cnt = 0; pszDataStart[cnt]; cnt++ )
	{
		if( pszDataStart[cnt] == '&' ) pClientRequest->iArgumentCount++;
		if( pszDataStart[cnt] == '=' ) iCntEqualChars++;
	}
	pClientRequest->iArgumentCount++;

	if( iCntEqualChars != pClientRequest->iArgumentCount ) 
	{
		pClientRequest->iArgumentCount = 0;
		pClientRequest->iArgumentParseError = 1;
		return;
	}

	pClientRequest->pArguments = (RSL_URLArgument*) calloc( pClientRequest->iArgumentCount, sizeof(RSL_URLArgument) );

	pItem = pszDataStart;
	cnt = 0;
	for( pItem = pszDataStart; *pItem && cnt < pClientRequest->iArgumentCount; pItem++ )
	{
		if( *pItem == '&' ) 
		{
			pClientRequest->pArguments[cnt].pszValue = pszDataStart;
			*pItem = '\0';
			cnt++;
			pszDataStart = pItem + 1;
		}
		if( *pItem == '=' ) 
		{
			pClientRequest->pArguments[cnt].pszKey = pszDataStart;
			*pItem = '\0';
			pszDataStart = pItem + 1;
		}
	}
	pClientRequest->pArguments[cnt].pszValue = pszDataStart;
}