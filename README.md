# SimpleRestServerLib

A simple lib for writing a rest server in C or C++.

* Supports HTTP or HTTPS via openSSL 

## Requirements
You need openssl and the openssl headers ( libssl-dev )

    apt-get install libssl-dev
    
## Usage 

1. Init server

    RSL_RestServer \*server = rsl_new_rest_server();
        
2. Set options

    * rsl_option_set_port( RSL_RestServer \*pS, int iPort );  // Required 
    * rsl_option_set_HTTPS( RSL_RestServer \*pS, int bHTTPSOn ); // Optinal
    * rsl_option_set_certificate_key_file_path( pS \*pRestServer, const char \* pszPath ); // Required with Https
    * rsl_option_set_certificate_file_path( pS \*pRestServer, const char \* pszPath ); // Required with Https
    * rsl_option_set_Timeout( RSL_RestServer \*pS, int iSec, int iMiliSec ); // Optinal
    * rsl_option_set_error_function( RSL_RestServer \*pS, RSL_ErrorFunction \*pErrorFunction ); // Optinal
    
3. Add responce functions

    rsl_option_set_responce_function( RSL_RestServer \*pS, RSL_ResponceFunction pRF, const char\* pszUrl, const char\* pszRequestMethod );
    
    * Request method can have this values: "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "TRACE", "OPTIONS", "CONNECT"
    * RSL_ResponceFunction is the function that's gets called, if a client request the specified url and with the specified request method. 
    * The Function return a string thats gets send to the client, http header included. It has the argumetns RSL_RestServer\* and RSL_ClientRequest\* 
    
    This is also optional, because you can't responce to every posible url. If a client request a url, that has not responce function set, a default, page not found, answer is send back.
   
4.  Call run function

    rsl_run( RSL_RestServer \*pRestServer );
    
## Examples
[HttpRestServer](examples/ReturnRandNumberHttp.c#top) - returns random number in JSON format.
