'''
3.5. Parameter Transmission


   When making an OAuth-authenticated request, protocol parameters as
   well as any other parameter using the "oauth_" prefix SHALL be
   included in the request using one and only one of the following
   locations, listed in order of decreasing preference:

   1.  The HTTP "Authorization" header field as described in
       Section 3.5.1.

   2.  The HTTP request entity-body as described in Section 3.5.2.

   3.  The HTTP request URI query as described in Section 3.5.3.

   In addition to these three methods, future extensions MAY define
   other methods for including protocol parameters in the request.
'''
from sga.oauth1.shared.helpers.encode import encode_parameters


def authorization_header_decode(request):
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
    http_authorization = request.META.get('HTTP_AUTHORIZATION').replace('OAuth',
                                                                        '')
    i = http_authorization.split(',')
    parameters = {unquote(http_authorization.split('=')[0]).strip():
                  unquote(http_authorization.split('=')[1]).strip()
                  for http_authorization in i}


def authorization_header_encode(parameters):
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
    headers = {"Authorization": "OAuth %s" % parameters, }
    return headers


def form_encoded_body_decode(result):
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


def form_encoded_body_encode(parameters):
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
    result = urlencode(parameters)
#    {
#        'oauth_token': access_token.oauth_key,
#        'oauth_token_secret': access_token.oauth_secret
#    })
    return HttpResponse(result, content_type='application/x-www-form-urlencoded')


def request_uri_query_encode():
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

def request_uri_query_decode():
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
    callback = callback % (request_token.oauth_key, request_token.verifier)
    return HttpResponseRedirect(callback)








