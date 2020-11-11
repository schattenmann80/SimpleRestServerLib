#include "../include/SimpleRestServerLib.h"

const char* Get_responce( RSL_RestServer *pRestServer, RSL_ClientRequest* pClientRequest )
{
	static const char reply[] = "HTTP/1.1 200 OK\r\n"
					"Connection: close\r\n"
					"Content-Type: application/json\r\n"
					"\r\n"
					"{ \"Message\": \"Hallo\" }\r\n";
	//puts("Body");
	//puts(pClientRequest->pszBody);
	return reply;
}

int main( int argc, char **argv )
{

	RSL_RestServer *server = rsl_new_rest_server();

	rsl_option_set_HTTPS( server, HTTPS );
	rsl_option_set_port( server, 15015 );
	rsl_option_set_Timeout( server, 5, 0 );
	rsl_option_set_certificate_file_path( server, "certificate/cert.pem" );
	rsl_option_set_certificate_key_file_path( server, "certificate/key.pem" );

	rsl_option_set_responce_function( server, Get_responce, "/", "GET" );

	rsl_run( server );
}