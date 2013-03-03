from django.http import HttpResponse
from sga.oauth1.shared.helpers.encode import encode_parameters
from urllib import urlencode
from urlparse import unquote


class AuthenticatedRequests(object):


    .get_full_path() uri
   HttpRequest.method method
   HttpRequest.GET request_paramentes
   HttpRequest.body body
   HttpRequest.META.get('HTTP_AUTHORIZATION').replace('OAuth', '') authorize header




    def __init__(self, request):
        self.request = request
        headers

    def get_method(self):
        self.get_full_path()

    def get_uri(self):
        self.get_full_path()

    def get_query_parameters(self):
        self.get_full_path()

    def get_body(self):
        self.get_full_path()

    def get_authorization_header(self):
        self.get_full_path()

    def __getattr__(self, attr):
        """Everything else is delegated to the object"""
        return getattr(self.request, attr)

    def verify_signature(self):
        pass

    def sign(self):
        pass

    def authorization_header_decode(self, request):
        '''
        3.5.1. Authorization Header

           Protocol parameters can be transmitted using the HTTP "Authorization"
           header field as defined by [RFC2617] with the auth-scheme name set to
           "OAuth" (case insensitive).

           For example:

             Authorization: OAuth realm="Example",
                oauth_consumer_key="0685bd9184jfhq22",
                oauth_token="ad180jjd733klru7",
                oauth_signature_method="HMAC-SHA1",
                oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
                oauth_timestamp="137131200",
                oauth_nonce="4572616e48616d6d65724c61686176",
                oauth_version="1.0"

           Protocol parameters SHALL be included in the "Authorization" header
           field as follows:

           1.  Parameter names and values are encoded per Parameter Encoding
               (Section 3.6).

           2.  Each parameter's name is immediately followed by an "=" character
               (ASCII code 61), a """ character (ASCII code 34), the parameter
               value (MAY be empty), and another """ character (ASCII code 34).

           3.  Parameters are separated by a "," character (ASCII code 44) and
               OPTIONAL linear whitespace per [RFC2617].

           4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
               [RFC2617] section 1.2.

           Servers MAY indicate their support for the "OAuth" auth-scheme by
           returning the HTTP "WWW-Authenticate" response header field upon
           client requests for protected resources.  As per [RFC2617], such a
           response MAY include additional HTTP "WWW-Authenticate" header
           fields:

           For example:

             WWW-Authenticate: OAuth realm="http://server.example.com/"

           The realm parameter defines a protection realm per [RFC2617], Section
           1.2.
        '''
        http_authorization = request.META.get('HTTP_AUTHORIZATION').replace('OAuth', '')
        i = http_authorization.split(',')
        parameters = {unquote(http_authorization.split('=')[0]).strip():
                      unquote(http_authorization.split('=')[1]).strip()
                      for http_authorization in i}
        return parameters

    def authorization_header_encode(self, parameters):
        '''
        3.5.1. Authorization Header

           Protocol parameters can be transmitted using the HTTP "Authorization"
           header field as defined by [RFC2617] with the auth-scheme name set to
           "OAuth" (case insensitive).

           For example:

             Authorization: OAuth realm="Example",
                oauth_consumer_key="0685bd9184jfhq22",
                oauth_token="ad180jjd733klru7",
                oauth_signature_method="HMAC-SHA1",
                oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
                oauth_timestamp="137131200",
                oauth_nonce="4572616e48616d6d65724c61686176",
                oauth_version="1.0"

           Protocol parameters SHALL be included in the "Authorization" header
           field as follows:

           1.  Parameter names and values are encoded per Parameter Encoding
               (Section 3.6).

           2.  Each parameter's name is immediately followed by an "=" character
               (ASCII code 61), a """ character (ASCII code 34), the parameter
               value (MAY be empty), and another """ character (ASCII code 34).

           3.  Parameters are separated by a "," character (ASCII code 44) and
               OPTIONAL linear whitespace per [RFC2617].

           4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
               [RFC2617] section 1.2.

           Servers MAY indicate their support for the "OAuth" auth-scheme by
           returning the HTTP "WWW-Authenticate" response header field upon
           client requests for protected resources.  As per [RFC2617], such a
           response MAY include additional HTTP "WWW-Authenticate" header
           fields:

           For example:

             WWW-Authenticate: OAuth realm="http://server.example.com/"

           The realm parameter defines a protection realm per [RFC2617], Section
           1.2.
        '''
        parameters = encode_parameters(parameters)
        self.headers['Authorization'] = "OAuth %s" % parameters

    def form_encoded_body_decode(self, result):
        '''
        3.5.2. Form-Encoded Body

           Protocol parameters can be transmitted in the HTTP request entity-
           body, but only if the following REQUIRED conditions are met:

           o  The entity-body is single-part.

           o  The entity-body follows the encoding requirements of the
              "application/x-www-form-urlencoded" content-type as defined by
              [W3C.REC-html40-19980424].

           o  The HTTP request entity-header includes the "Content-Type" header
              field set to "application/x-www-form-urlencoded".

           For example (line breaks are for display purposes only):

             oauth_consumer_key=0685bd9184jfhq22&oauth_token=ad180jjd733klr
             u7&oauth_signature_method=HMAC-SHA1&oauth_signature=wOJIO9A2W5
             mFwDgiDvZbTSMK%2FPY%3D&oauth_timestamp=137131200&oauth_nonce=4
             572616e48616d6d65724c61686176&oauth_version=1.0

           The entity-body MAY include other request-specific parameters, in
           which case, the protocol parameters SHOULD be appended following the
           request-specific parameters, properly separated by an "&" character
           (ASCII code 38).
        '''
        i = result.split('&')
        parameters = {a.split('=')[0].strip():
                      a.split('=')[1].strip()
                      for a in i}
        return parameters


    def form_encoded_body_encode(self, parameters):
        '''
        3.5.2. Form-Encoded Body

           Protocol parameters can be transmitted in the HTTP request entity-
           body, but only if the following REQUIRED conditions are met:

           o  The entity-body is single-part.

           o  The entity-body follows the encoding requirements of the
              "application/x-www-form-urlencoded" content-type as defined by
              [W3C.REC-html40-19980424].

           o  The HTTP request entity-header includes the "Content-Type" header
              field set to "application/x-www-form-urlencoded".

           For example (line breaks are for display purposes only):

             oauth_consumer_key=0685bd9184jfhq22&oauth_token=ad180jjd733klr
             u7&oauth_signature_method=HMAC-SHA1&oauth_signature=wOJIO9A2W5
             mFwDgiDvZbTSMK%2FPY%3D&oauth_timestamp=137131200&oauth_nonce=4
             572616e48616d6d65724c61686176&oauth_version=1.0

           The entity-body MAY include other request-specific parameters, in
           which case, the protocol parameters SHOULD be appended following the
           request-specific parameters, properly separated by an "&" character
           (ASCII code 38).
        '''
        self.body = urlencode(parameters)
        self.content_type='application/x-www-form-urlencoded')


    def request_uri_query_encode(self, parameters):
        '''
        3.5.3. Request URI Query

           Protocol parameters can be transmitted by being added to the HTTP
           request URI as a query parameter as defined by [RFC3986], Section 3.

           For example (line breaks are for display purposes only):

             GET /example/path?oauth_consumer_key=0685bd9184jfhq22&
             oauth_token=ad180jjd733klru7&oauth_signature_method=HM
             AC-SHA1&oauth_signature=wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%
             3D&oauth_timestamp=137131200&oauth_nonce=4572616e48616
             d6d65724c61686176&oauth_version=1.0 HTTP/1.1

           The request URI MAY include other request-specific query parameters,
           in which case, the protocol parameters SHOULD be appended following
           the request-specific parameters, properly separated by an "&"
           character (ASCII code 38).
        '''
        self.query_encode = parameters

    def request_uri_query_decode(self):
        '''
        3.5.3. Request URI Query

           Protocol parameters can be transmitted by being added to the HTTP
           request URI as a query parameter as defined by [RFC3986], Section 3.

           For example (line breaks are for display purposes only):

             GET /example/path?oauth_consumer_key=0685bd9184jfhq22&
             oauth_token=ad180jjd733klru7&oauth_signature_method=HM
             AC-SHA1&oauth_signature=wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%
             3D&oauth_timestamp=137131200&oauth_nonce=4572616e48616
             d6d65724c61686176&oauth_version=1.0 HTTP/1.1

           The request URI MAY include other request-specific query parameters,
           in which case, the protocol parameters SHOULD be appended following
           the request-specific parameters, properly separated by an "&"
           character (ASCII code 38).
        '''
        return self.query_encode


        callback = callback % (request_token.oauth_key, request_token.verifier)
        return HttpResponseRedirect(callback)


    def verify(self):
        
    try:
        oauth_consumer_key = parameters['oauth_consumer_key']
        oauth_timestamp = parameters['oauth_timestamp']
        oauth_signature = parameters['oauth_signature']
        oauth_nonce = parameters['oauth_nonce']
        oauth_callback = parameters['oauth_callback']
    except Exception, e:
        return HttpMissingRequiredParameter()


    '''
      o  Recalculating the request signature independently as described in
         Section 3.4 and comparing it to the value received from the client
         via the "oauth_signature" parameter.
    '''
    signature = parameter[signature]
    validate(self, signature)
    
    
    '''
      o  If using the "HMAC-SHA1" or "RSA-SHA1" signature methods, ensuring
         that the combination of nonce/timestamp/token (if present)
         received from the client has not been used before in a previous
         request (the server MAY reject requests with stale timestamps as
         described in Section 3.3).
    '''
    if not check_timestamp(oauth_timestamp):
        return HttpInvalidExpiredToken()

    if Nonce.objects.filter(nounce_key=oauth_nonce):
        return HttpInvalidUsedNonce()
    else:
        nonce = Nonce()
        nonce.nonce_key = oauth_nonce
        nonce.save()

    '''
       o  If a token is present, verifying the scope and status of the
          client authorization as represented by the token (the server MAY
          choose to restrict token usage to the client to which it was
          issued).
    '''
    
    '''
       o  If the "oauth_version" parameter is present, ensuring its value is
          "1.0".
    '''
        if parameters['version']:
            validate 1.0
        


        validate_client_credentials():
            try:
        consumer = ClientCredentials.objects.get(oauth_key=oauth_consumer_key)
    except Exception, e:
        return HttpInvalidConsumerKey()
    
    
        validate_temporary_credentials():
        
        validate_token_credentials():    