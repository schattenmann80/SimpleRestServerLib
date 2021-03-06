#include "../include/SimpleRestServerLib.h"

const char* Get_responce( RSL_RestServer *pRestServer, RSL_ClientRequest* pClientRequest )
{
	static const char reply[] = "HTTP/1.1 200 OK\r\n"
					"Connection: close\r\n"
					"Content-Type: application/json\r\n"
					"\r\n"
					"{ \"Message\": \"Hallo\", \"Number\": %d }\r\n";
	static char buffer[128];
	int cnt = 0;

	if( pClientRequest->pszBody && *pClientRequest->pszBody != 0 ) puts(pClientRequest->pszBody); 

	for( ; cnt < pClientRequest->iArgumentCount; cnt++ )
	{
		printf( "key: %s, value: %s\n", pClientRequest->pArguments[cnt].pszKey,  pClientRequest->pArguments[cnt].pszValue );
	}

	sprintf( buffer, reply, rand() );

	return buffer;
}

int main( int argc, char **argv )
{

	RSL_RestServer *server = rsl_new_rest_server();

	rsl_option_set_HTTPS( server, HTTPS );
	rsl_option_set_port( server, 15015 );
	rsl_option_set_Timeout( server, 5, 0 );
	rsl_option_set_certificate_file_path( server, "certificate/cert.pem" );
	rsl_option_set_certificate_key_file_path( server, "certificate/key.pem" );

	rsl_option_add_responce_function( server, Get_responce, "/", "GET" );

	rsl_run( server );
}