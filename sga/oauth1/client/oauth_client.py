from django.conf import settings
from django.conf.urls import patterns, url
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from sga.oauth1.shared.reponses import HttpInvalidExpiredToken
from urllib2 import URLError
import httplib
import time
import urllib2


class OauthClient():
    '''
    2. Redirection-Based Authorization

       OAuth uses tokens to represent the authorization granted to the
       client by the resource owner.  Typically, token credentials are
       issued by the server at the resource owner's request, after
       authenticating the resource owner's identity (usually using a
       username and password).

       There are many ways in which a server can facilitate the provisioning
       of token credentials.  This section defines one such way, using HTTP
       redirections and the resource owner's user-agent.  This redirection-
       based authorization method includes three steps:

       1.  The client obtains a set of temporary credentials from the server
           (in the form of an identifier and shared-secret).  The temporary
           credentials are used to identify the access request throughout
           the authorization process.

       2.  The resource owner authorizes the server to grant the client's
           access request (identified by the temporary credentials).

       3.  The client uses the temporary credentials to request a set of
           token credentials from the server, which will enable it to access
           the resource owner's protected resources.

       The server MUST revoke the temporary credentials after being used
       once to obtain the token credentials.  It is RECOMMENDED that the
       temporary credentials have a limited lifetime.  Servers SHOULD enable
       resource owners to revoke token credentials after they have been
       issued to clients.

       In order for the client to perform these steps, the server needs to
       advertise the URIs of the following three endpoints:

       Temporary Credential Request
             The endpoint used by the client to obtain a set of temporary
             credentials as described in Section 2.1.

       Resource Owner Authorization
             The endpoint to which the resource owner is redirected to grant
             authorization as described in Section 2.2.

       Token Request
             The endpoint used by the client to request a set of token
             credentials using the set of temporary credentials as described
             in Section 2.3.

       The three URIs advertised by the server MAY include a query component
       as defined by [RFC3986], Section 3, but if present, the query MUST
       NOT contain any parameters beginning with the "oauth_" prefix, to
       avoid conflicts with the protocol parameters added to the URIs when
       used.

       The methods in which the server advertises and documents its three
       endpoints are beyond the scope of this specification.  Clients should
       avoid making assumptions about the size of tokens and other server-
       generated values, which are left undefined by this specification.  In
       addition, protocol parameters MAY include values that require
       encoding when transmitted.  Clients and servers should not make
       assumptions about the possible range of their values.
    '''
    def __init__(self, settings, session):
        '''
        Settings
        '''
        self.AVALAIBLE_SIGNATURES = {
                        'HMAC-SHA1': 'HMAC-SHA1',
                        'RSA-SHA1': 'RSA-SHA1',
                        'PLAINTEXT': 'PLAINTEXT'
                      }
        self.name = 'test'
        self.app_name = 'test'

        self.TEMPORARY_CREDENTIAL_REQUEST_ENDPOINT = "http://127.0.0.1:8001/oauthserver/reques"
        self.RESOURCE_OWNER_AUTHORIZATION_ENDPOINT = "http://127.0.0.1:8001/oauthserver/authorization?oauth_token=%s"
        self.TOKEN_REQUEST_ENDPOINT = "http://127.0.0.1:8001/oauthserver/access"

        self.CALLBACK_URL = 'http://127.0.0.1:8000/oauthclient/callback/test/?oauth_token=%s&oauth_verifier=%s'

        self.CLIENT_IDENTIFIER = ''
        self.CLIENT_SHARED_SECRET = ''

        self.SIGNATURE_METHOD = self.AVALAIBLE_SIGNATURES['HMAC-SHA1']
        self.OAUTH_VERSION = '1.0'

#    def get_provider_time(self, method_name, parameters=None):
#        namespace = self.NAMESPACE
#        path_request = '/get_provider_time/'
#        url = self.OAUTH_URL
#        oauth_port = self.OAUTH_PORT
#        try:
#            oauth_token = self.session.get('OAUTH_ACCESS_TOKEN')[namespace]
#        except:
#            raise OauthAccessTokenNoValid
#        parameters = {
#                      'oauth_token': oauth_token,
#                      'oauth_consumer_key': self.settings['OAUTH_CONSUMER_KEY'],
#                      'oauth_signature_method': 'HMAC-SHA1',
#                      'oauth_timestamp': int(time.time()),
#                      'oauth_nonce': generate_nonce(length=8),
#                      'oauth_version': '1.0'
#                      }
#        
#        oauth_signature = sign_request('POST',
#                                       parameters,
#                                       self.OAUTH_CONSUMER_SECRET)
#        parameters['oauth_signature'] = oauth_signature
#        result, status = fetch_oauth(url,
#                                     oauth_port,
#                                     path_request,
#                                     'POST',
#                                     parameters)
#        if status == 401:
#            raise OauthAccessTokenNoValid
#        elif status == 200:
#            return result
#        else:
#            raise OauthError

    def get_tokens(self):
        namespace = self.NAMESPACE
        return HttpResponseRedirect(reverse('sgaoauth_%s_obtain_request_token' % namespace))

    '''
    Views
    '''
    def obtain_request_token(self, request, namespace):
        """
        2.1. Temporary Credentials

        The client obtains a set of temporary credentials from the server by
        making an authenticated (Section 3) HTTP "POST" request to the
        Temporary Credential Request endpoint (unless the server advertises
        another HTTP request method for the client to use).  The client
        constructs a request URI by adding the following REQUIRED parameter
        to the request (in addition to the other protocol parameters, using
        the same parameter transmission method):

        oauth_callback:  An absolute URI back to which the server will
                        redirect the resource owner when the Resource Owner
                        Authorization step (Section 2.2) is completed.  If
                        the client is unable to receive callbacks or a
                        callback URI has been established via other means,
                        the parameter value MUST be set to "oob" (case
                        sensitive), to indicate an out-of-band
                        configuration.

        Servers MAY specify additional parameters.

        When making the request, the client authenticates using only the
        client credentials.  The client MAY omit the empty "oauth_token"
        protocol parameter from the request and MUST use the empty string as
        the token secret value.

        Since the request results in the transmission of plain text
        credentials in the HTTP response, the server MUST require the use of
        a transport-layer mechanisms such as TLS or Secure Socket Layer (SSL)
        (or a secure channel with equivalent protections).

        For example, the client makes the following HTTPS request:

         POST /request_temp_credentials HTTP/1.1
         Host: server.example.com
         Authorization: OAuth realm="Example",
            oauth_consumer_key="jd83jd92dhsh93js",
            oauth_signature_method="PLAINTEXT",
            oauth_callback="http%3A%2F%2Fclient.example.net%2Fcb%3Fx%3D1",
            oauth_signature="ja893SD9%26"

        The server MUST verify (Section 3.2) the request and if valid,
        respond back to the client with a set of temporary credentials (in
        the form of an identifier and shared-secret).  The temporary
        credentials are included in the HTTP response body using the
        "application/x-www-form-urlencoded" content type as defined by
        [W3C.REC-html40-19980424] with a 200 status code (OK).

        The response contains the following REQUIRED parameters:

        oauth_token
             The temporary credentials identifier.

        oauth_token_secret
             The temporary credentials shared-secret.

        oauth_callback_confirmed
             MUST be present and set to "true".  The parameter is used to
             differentiate from previous versions of the protocol.

        Note that even though the parameter names include the term 'token',
        these credentials are not token credentials, but are used in the next
        two steps in a similar manner to token credentials.

        For example (line breaks are for display purposes only):

         HTTP/1.1 200 OK
         Content-Type: application/x-www-form-urlencoded

         oauth_token=hdk48Djdsa&oauth_token_secret=xyz4992k83j47x0b&
         oauth_callback_confirmed=true
        """
        url = self.TEMPORARY_CREDENTIAL_REQUEST_ENDPOINT
        oauth_callback = self.CALLBACK_URL
        authenticate_request = AuthenticateRequest()
        result = authenticate_request.make_request(url, oauth_callback=oauth_callback)
        parameters = form_encoded_body_decode(result)
        oauth_token = parameters['oauth_token']
        return self.directs_user_service_provider(oauth_token, namespace)


    def directs_user_service_provider(self, oauth_token, namespace):
        '''
        2.2. Resource Owner Authorization

        Before the client requests a set of token credentials from the
        server, it MUST send the user to the server to authorize the request.
        The client constructs a request URI by adding the following REQUIRED
        query parameter to the Resource Owner Authorization endpoint URI:

        oauth_token
              The temporary credentials identifier obtained in Section 2.1 in
              the "oauth_token" parameter.  Servers MAY declare this
              parameter as OPTIONAL, in which case they MUST provide a way
              for the resource owner to indicate the identifier through other
              means.

        Servers MAY specify additional parameters.

        The client directs the resource owner to the constructed URI using an
        HTTP redirection response, or by other means available to it via the
        resource owner's user-agent.  The request MUST use the HTTP "GET"
        method.

        For example, the client redirects the resource owner's user-agent to
        make the following HTTPS request:

          GET /authorize_access?oauth_token=hdk48Djdsa HTTP/1.1
          Host: server.example.com

        The way in which the server handles the authorization request,
        including whether it uses a secure channel such as TLS/SSL is beyond
        the scope of this specification.  However, the server MUST first
        verify the identity of the resource owner.

        When asking the resource owner to authorize the requested access, the
        server SHOULD present to the resource owner information about the
        client requesting access based on the association of the temporary
        credentials with the client identity.  When displaying any such
        information, the server SHOULD indicate if the information has been
        verified.

        After receiving an authorization decision from the resource owner,
        the server redirects the resource owner to the callback URI if one
        was provided in the "oauth_callback" parameter or by other means.

        To make sure that the resource owner granting access is the same
        resource owner returning back to the client to complete the process,
        the server MUST generate a verification code: an unguessable value
        passed to the client via the resource owner and REQUIRED to complete
        the process.  The server constructs the request URI by adding the
        following REQUIRED parameters to the callback URI query component:

        oauth_token
              The temporary credentials identifier received from the client.

        oauth_verifier
              The verification code.

        If the callback URI already includes a query component, the server
        MUST append the OAuth parameters to the end of the existing query.

        For example, the server redirects the resource owner's user-agent to
        make the following HTTP request:

          GET /cb?x=1&oauth_token=hdk48Djdsa&oauth_verifier=473f82d3 HTTP/1.1
          Host: client.example.net

        If the client did not provide a callback URI, the server SHOULD
        display the value of the verification code, and instruct the resource
        owner to manually inform the client that authorization is completed.
        If the server knows a client to be running on a limited device, it
        SHOULD ensure that the verifier value is suitable for manual entry.
        '''
        path_authorize = self.OAUTH_AUTHORIZATION_REQUEST_TOKEN_PATH
        url_server = self.OAUTH_URL
        port_server = self.OAUTH_PORT
        url = 'http://%s:%s%s' % (url_server, port_server, path_authorize)
        return HttpResponseRedirect(url % oauth_token)


    def callback(self, request, namespace):
        '''
        2.3. Token Credentials

        The client obtains a set of token credentials from the server by
        making an authenticated (Section 3) HTTP "POST" request to the Token
        Request endpoint (unless the server advertises another HTTP request
        method for the client to use).  The client constructs a request URI
        by adding the following REQUIRED parameter to the request (in
        addition to the other protocol parameters, using the same parameter
        transmission method):

        oauth_verifier
             The verification code received from the server in the previous
             step.

        When making the request, the client authenticates using the client
        credentials as well as the temporary credentials.  The temporary
        credentials are used as a substitute for token credentials in the
        authenticated request and transmitted using the "oauth_token"
        parameter.

        Since the request results in the transmission of plain text
        credentials in the HTTP response, the server MUST require the use of
        a transport-layer mechanism such as TLS or SSL (or a secure channel
        with equivalent protections).

        For example, the client makes the following HTTPS request:

         POST /request_token HTTP/1.1
         Host: server.example.com
         Authorization: OAuth realm="Example",
            oauth_consumer_key="jd83jd92dhsh93js",
            oauth_token="hdk48Djdsa",
            oauth_signature_method="PLAINTEXT",
            oauth_verifier="473f82d3",
            oauth_signature="ja893SD9%26xyz4992k83j47x0b"

        The server MUST verify (Section 3.2) the validity of the request,
        ensure that the resource owner has authorized the provisioning of
        token credentials to the client, and ensure that the temporary
        credentials have not expired or been used before.  The server MUST
        also verify the verification code received from the client.  If the
        request is valid and authorized, the token credentials are included
        in the HTTP response body using the
        "application/x-www-form-urlencoded" content type as defined by
        [W3C.REC-html40-19980424] with a 200 status code (OK).

        The response contains the following REQUIRED parameters:

        oauth_token
             The token identifier.

        oauth_token_secret
             The token shared-secret.

        For example:

         HTTP/1.1 200 OK
         Content-Type: application/x-www-form-urlencoded

         oauth_token=j49ddk933skd9dks&oauth_token_secret=ll399dj47dskfjdk

        The server must retain the scope, duration, and other attributes
        approved by the resource owner, and enforce these restrictions when
        receiving a client request made with the token credentials issued.

        Once the client receives and stores the token credentials, it can
        proceed to access protected resources on behalf of the resource owner
        by making authenticated requests (Section 3) using the client
        credentials together with the token credentials received.
        '''

        #Variables
        oauth_verifier = request.GET.get('oauth_verifier')
        oauth_token = request.GET.get('oauth_token')
#        oauth_consumer_key = self.OAUTH_CONSUMER_KEY
#        oauth_signature_method = self.SIGNATURE_METHOD
#        oauth_consumer_secret = self.OAUTH_CONSUMER_SECRET
#        oauth_nonce = generate_nonce(length=8)
#        oauth_timestamp = int(time.time())
#        parameters = {
#                        'oauth_token': oauth_token,
#                        'oauth_consumer_key': oauth_consumer_key, 
#                        'oauth_signature_method': oauth_signature_method,
#                        'oauth_timestamp': oauth_timestamp,
#                        'oauth_nonce': oauth_nonce,
#                        'oauth_verifier': oauth_verifier,
#                      }
#        oauth_signature = sign_request('POST',
#                                       parameters,
#                                       oauth_consumer_secret)
#        parameters['oauth_signature'] = oauth_signature

        authenticate_request = AuthenticateRequest()
        result = authenticate_request.make_request(url, oauth_callback=oauth_callback)
        i = result.split('&')
        parameters = {a.split('=')[0].strip(): a.split('=')[1].strip() for a in i}
        if 'OAUTH_ACCESS_TOKEN' not in request.session:
            request.session['OAUTH_ACCESS_TOKEN'] = {}
        request.session['OAUTH_ACCESS_TOKEN'][namespace] = parameters['oauth_token']
        return HttpResponseRedirect('/') #TODO: Return to initial request


    '''
    Urls
    '''
    def get_urls(self):
        namespace = self.NAMESPACE
        urlpatterns = patterns('',
           url(r'^obtain_request_token/%s/' % namespace,
               self.obtain_request_token,
               name='sgaoauth_%s_obtain_request_token' % namespace,),
           url(r'^callback/%s/' % namespace,
               self.callback,
               name='sgaoauth_%s_oauth_callback' % namespace,),
        )
        return urlpatterns

    @property
    def urls(self):
        return self.get_urls(), self.app_name, self.name



def authenticate_request(url, **kwargs):
    '''
    3.1. Making Requests

       An authenticated request includes several protocol parameters.  Each
       parameter name begins with the "oauth_" prefix, and the parameter
       names and values are case sensitive.  Clients make authenticated
       requests by calculating the values of a set of protocol parameters
       and adding them to the HTTP request as follows:

       1.  The client assigns value to each of these REQUIRED (unless
           specified otherwise) protocol parameters:

           oauth_consumer_key
             The identifier portion of the client credentials (equivalent to
             a username).  The parameter name reflects a deprecated term
             (Consumer Key) used in previous revisions of the specification,
             and has been retained to maintain backward compatibility.

           oauth_token
             The token value used to associate the request with the resource
             owner.  If the request is not associated with a resource owner
             (no token available), clients MAY omit the parameter.

           oauth_signature_method
             The name of the signature method used by the client to sign the
             request, as defined in Section 3.4.

           oauth_timestamp
             The timestamp value as defined in Section 3.3.  The parameter
             MAY be omitted when using the "PLAINTEXT" signature method.

           oauth_nonce
             The nonce value as defined in Section 3.3.  The parameter MAY
             be omitted when using the "PLAINTEXT" signature method.

           oauth_version
             OPTIONAL.  If present, MUST be set to "1.0".  Provides the
             version of the authentication process as defined in this
             specification.

       2.  The protocol parameters are added to the request using one of the
           transmission methods listed in Section 3.5.  Each parameter MUST
           NOT appear more than once per request.

       3.  The client calculates and assigns the value of the
           "oauth_signature" parameter as described in Section 3.4 and adds
           the parameter to the request using the same method as in the
           previous step.

       4.  The client sends the authenticated HTTP request to the server.

       For example, to make the following HTTP request authenticated (the
       "c2&a3=2+q" string in the following examples is used to illustrate
       the impact of a form-encoded entity-body):

         POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
         Host: example.com
         Content-Type: application/x-www-form-urlencoded    
         c2&a3=2+q

       The client assigns values to the following protocol parameters using
       its client credentials, token credentials, the current timestamp, a
       uniquely generated nonce, and indicates that it will use the
       "HMAC-SHA1" signature method:

         oauth_consumer_key:     9djdj82h48djs9d2
         oauth_token:            kkk9d7dh3k39sjv7
         oauth_signature_method: HMAC-SHA1
         oauth_timestamp:        137131201
         oauth_nonce:            7d8f3e4a

       The client adds the protocol parameters to the request using the
       OAuth HTTP "Authorization" header field:

         Authorization: OAuth realm="Example",
                        oauth_consumer_key="9djdj82h48djs9d2",
                        oauth_token="kkk9d7dh3k39sjv7",
                        oauth_signature_method="HMAC-SHA1",
                        oauth_timestamp="137131201",
                        oauth_nonce="7d8f3e4a"

       Then, it calculates the value of the "oauth_signature" parameter
       (using client secret "j49sk3j29djd" and token secret "dh893hdasih9"),
       adds it to the request, and sends the HTTP request to the server:

         POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
         Host: example.com
         Content-Type: application/x-www-form-urlencoded
         Authorization: OAuth realm="Example",
                        oauth_consumer_key="9djdj82h48djs9d2",
                        oauth_token="kkk9d7dh3k39sjv7",
                        oauth_signature_method="HMAC-SHA1",
                        oauth_timestamp="137131201",
                        oauth_nonce="7d8f3e4a",
                        oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
         c2&a3=2+q
    '''
    #Parameters
    oauth_consumer_key = self.OAUTH_CONSUMER_KEY
    oauth_signature_method = self.SIGNATURE_METHOD
    oauth_consumer_secret = self.OAUTH_CONSUMER_SECRET
    oauth_callback = self.OAUTH_CALLBACK_URL
    oauth_timestamp = int(time.time())
    oauth_nonce = generate_nonce(length=8)

    parameters = {
                  'oauth_consumer_key': oauth_consumer_key,
                  'oauth_signature_method': oauth_signature_method,
                  'oauth_consumer_secret': oauth_consumer_secret,
                  'oauth_timestamp': oauth_timestamp,
                  'oauth_nonce': oauth_nonce,
                  }

    parameters.update(**kwargs)
    if self.OAUTH_VERSION:
        parameters['oauth_version'] = self.OAUTH_VERSION
    headers = {"Authorization": "OAuth %s" % parameters, }
    request = urllib2.Request(url, headers)
    oauth_signature = sign_request(request)
    parameters['oauth_signature'] = oauth_signature
    parameters = encode_parameters(parameters) #Todo: check this

    request.add_header("Authorization", "OAuth %s" % parameters)

    conn = httplib.HTTPConnection(url, port)
    
    conn.request('POST', path, headers=headers)
    
    response = conn.getresponse()
    status = response.status
    data = response.read()
    conn.close()



    if status == 200:
        return data
    elif status == 401:
        return HttpInvalidExpiredToken()
    else:
        return HttpResponse('Unknown error', status=500)


