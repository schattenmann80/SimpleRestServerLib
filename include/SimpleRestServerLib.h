#ifndef SIMPLE_REST_SERVER_LIB
#define SIMPLE_REST_SERVER_LIB

#include <openssl/ssl.h>

#define HTTPS 1
#define HTTP 0

typedef struct RSL_RestServer RSL_RestServer;
typedef struct RSL_ClientRequest RSL_ClientRequest;
typedef struct RSL_Responce RSL_Responce;
typedef struct RSL_URLArgument RSL_URLArgument;

typedef int RSL_ErrorFunction( const char* pszError_Message, int bIsOpenSSL );
typedef const char* RSL_ResponceFunction( RSL_RestServer* pRestServer, RSL_ClientRequest* pClientRequest );

typedef struct RSL_ClientRequest
{
	char* pszUrl;
	char pszRequestMethod[16];
	char* pszBody;
	char* pszHeaderArguments;
	char* pszHttpVerison;

	RSL_URLArgument *pArguments;
	size_t iArgumentCount;
	int iArgumentParseError;
} RSL_ClientRequest;

typedef struct RSL_URLArgument
{
	const char* pszKey;
	const char* pszValue;
}RSL_URLArgument;

extern RSL_RestServer* rsl_new_rest_server();
extern void rsl_clean_and_free_rest_server( RSL_RestServer *pRestServer );
extern void rsl_run( RSL_RestServer *pRestServer );

extern int rsl_option_set_port( RSL_RestServer *pRestServer, int iPort );
extern int rsl_option_set_HTTPS( RSL_RestServer *pRestServer, int bHTTPSOn );
extern int rsl_option_set_certificate_key_file_path( RSL_RestServer *pRestServer, const char * pszPath );
extern int rsl_option_set_certificate_file_path( RSL_RestServer *pRestServer, const char * pszPath );
extern int rsl_option_set_Timeout( RSL_RestServer *pRestServer, int iSec, int iMiliSec );
extern int rsl_option_set_error_function( RSL_RestServer *pRestServer, RSL_ErrorFunction *pErrorFunction );
extern int rsl_option_add_responce_function( RSL_RestServer *pRestServer, 
											RSL_ResponceFunction pResponceFunction, 
											const char* pszUrl,
											const char* pszRequestMethod );
extern int rsl_option_set_verbose( RSL_RestServer *pRestServer, int bVerbose );

#endif