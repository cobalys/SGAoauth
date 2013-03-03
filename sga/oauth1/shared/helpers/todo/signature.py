from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from sga_oauth.shared.helpers.encode import encode_oauth
from urlparse import urlparse
import binascii
import hmac
import urllib
try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    import sha


def encode_parameter(s):
    if isinstance(s, basestring):
        return urllib.quote(s.encode('utf8'), safe='~')
    else:
        return s


def decode_parameter(s):
    if isinstance(s, basestring):
        return urllib.unquote(s.encode('utf8'))
    else:
        return s


def sign_hmac_sha1(signature_base_string,
                   oauth_consumer_secret,
                   token_shared_secret=None):
    '''
    3.4.2. HMAC-SHA1

       The "HMAC-SHA1" signature method uses the HMAC-SHA1 signature
       algorithm as defined in [RFC2104]:

         digest = HMAC-SHA1 (key, text)

       The HMAC-SHA1 function variables are used in following way:

       text    is set to the value of the signature base string from
               Section 3.4.1.1.

       key     is set to the concatenated values of:

               1.  The client shared-secret, after being encoded
                   (Section 3.6).

               2.  An "&" character (ASCII code 38), which MUST be included
                   even when either secret is empty.

               3.  The token shared-secret, after being encoded
                   (Section 3.6).

       digest  is used to set the value of the "oauth_signature" protocol
               parameter, after the result octet string is base64-encoded
               per [RFC2045], Section 6.8.
    '''
    key = '&'.join(
                   encode_parameter(oauth_consumer_secret),
                   encode_parameter(token_shared_secret)
                   )
    text = signature_base_string
    digest = hmac.new(key, text, sha).digest()
    return binascii.b2a_base64(digest)[:-1]


def sign_rsa_sha1(signature_base_string, rsa_privatekey):
    '''
    3.4.3. RSA-SHA1

       The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
       algorithm as defined in [RFC3447], Section 8.2 (also known as
       PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
       use this method, the client MUST have established client credentials
       with the server that included its RSA public key (in a manner that is
       beyond the scope of this specification).

       The signature base string is signed using the client's RSA private
       key per [RFC3447], Section 8.2.1:

         S = RSASSA-PKCS1-V1_5-SIGN (K, M)

       Where:

       K     is set to the client's RSA private key,

       M     is set to the value of the signature base string from
             Section 3.4.1.1, and

       S     is the result signature used to set the value of the
             "oauth_signature" protocol parameter, after the result octet
             string is base64-encoded per [RFC2045] section 6.8.

       The server verifies the signature per [RFC3447] section 8.2.2:

         RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

       Where:

       (n, e) is set to the client's RSA public key,

       M      is set to the value of the signature base string from
              Section 3.4.1.1, and

       S      is set to the octet string value of the "oauth_signature"
              protocol parameter received from the client.
    '''
    key = rsa_privatekey
    text = signature_base_string
    hash = SHA.new(text).digest()
    signature = key.sign(hash, '')[0]
    return binascii.b2a_base64(signature)[:-1]


def verify_rsa_sha1(signature_base_string, rsa_publickey, signature):
    '''
    3.4.3. RSA-SHA1

       The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
       algorithm as defined in [RFC3447], Section 8.2 (also known as
       PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
       use this method, the client MUST have established client credentials
       with the server that included its RSA public key (in a manner that is
       beyond the scope of this specification).

       The signature base string is signed using the client's RSA private
       key per [RFC3447], Section 8.2.1:

         S = RSASSA-PKCS1-V1_5-SIGN (K, M)

       Where:

       K     is set to the client's RSA private key,

       M     is set to the value of the signature base string from
             Section 3.4.1.1, and

       S     is the result signature used to set the value of the
             "oauth_signature" protocol parameter, after the result octet
             string is base64-encoded per [RFC2045] section 6.8.

       The server verifies the signature per [RFC3447] section 8.2.2:

         RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

       Where:

       (n, e) is set to the client's RSA public key,

       M      is set to the value of the signature base string from
              Section 3.4.1.1, and

       S      is set to the octet string value of the "oauth_signature"
              protocol parameter received from the client.
    '''
    key = rsa_publickey
    text = signature_base_string
    hash = SHA.new(text).digest()
    signature = key.verify(hash, '')[0]
    binascii.b2a_base64(signature)[:-1]


def sign_plaintext(oauth_consumer_secret='', token_shared_secret=''):
    '''
    3.4.4. PLAINTEXT

       The "PLAINTEXT" method does not employ a signature algorithm.  It
       MUST be used with a transport-layer mechanism such as TLS or SSL (or
       sent over a secure channel with equivalent protections).  It does not
       utilize the signature base string or the "oauth_timestamp" and
       "oauth_nonce" parameters.

       The "oauth_signature" protocol parameter is set to the concatenated
       value of:

       1.  The client shared-secret, after being encoded (Section 3.6).

       2.  An "&" character (ASCII code 38), which MUST be included even
           when either secret is empty.

       3.  The token shared-secret, after being encoded (Section 3.6).
    '''
    return '%s&%s' % (oauth_consumer_secret, token_shared_secret)


def get_base_string(request_method,
                    resource_uri,
                    query_components,
                    parameters,
                    body_parameters
                    ):
    '''
    3.4.1. Signature Base String

       The signature base string is a consistent, reproducible concatenation
       of several of the HTTP request elements into a single string.  The
       string is used as an input to the "HMAC-SHA1" and "RSA-SHA1"
       signature methods.

       The signature base string includes the following components of the
       HTTP request:

       o  The HTTP request method (e.g., "GET", "POST", etc.).

       o  The authority as declared by the HTTP "Host" request header field.

       o  The path and query components of the request resource URI.

       o  The protocol parameters excluding the "oauth_signature".

       o  Parameters included in the request entity-body if they comply with
          the strict restrictions defined in Section 3.4.1.3.

       The signature base string does not cover the entire HTTP request.
       Most notably, it does not include the entity-body in most requests,
       nor does it include most HTTP entity-headers.  It is important to
       note that the server cannot verify the authenticity of the excluded
       request components without using additional protections such as SSL/
       TLS or other methods.


    3.4.1.1. String Construction

    The signature base string is constructed by concatenating together,
    in order, the following HTTP request elements:

    1.  The HTTP request method in uppercase.  For example: "HEAD",
        "GET", "POST", etc.  If the request uses a custom HTTP method, it
        MUST be encoded (Section 3.6).

    2.  An "&" character (ASCII code 38).

    3.  The base string URI from Section 3.4.1.2, after being encoded
        (Section 3.6).

    4.  An "&" character (ASCII code 38).

    5.  The request parameters as normalized in Section 3.4.1.3.2, after
        being encoded (Section 3.6).

    For example, the HTTP request:

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

    is represented by the following signature base string (line breaks
    are for display purposes only):

      POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
      %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
      key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
      ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
      9d7dh3k39sjv7

    '''
    base_string = "%s&%s&%s"
    request_method = request_method.upper()
    base_string_uri = get_base_uri(resource_uri)
    parameters = get_parameters(parameters)
    return base_string % (base_string, base_string_uri, parameters)


def get_base_uri(resource_uri):
    '''
    3.4.1.2. Base String URI

       The scheme, authority, and path of the request resource URI [RFC3986]
       are included by constructing an "http" or "https" URI representing
       the request resource (without the query or fragment) as follows:

       1.  The scheme and host MUST be in lowercase.

       2.  The host and port values MUST match the content of the HTTP
           request "Host" header field.

       3.  The port MUST be included if it is not the default port for the
           scheme, and MUST be excluded if it is the default.  Specifically,
           the port MUST be excluded when making an HTTP request [RFC2616]
           to port 80 or when making an HTTPS request [RFC2818] to port 443.
           All other non-default port numbers MUST be included.

       For example, the HTTP request:

         GET /r%20v/X?id=123 HTTP/1.1
         Host: EXAMPLE.COM:80
        http://example.com/r%20v/X?id=123
       is represented by the base string URI: "http://example.com/r%20v/X".

       In another example, the HTTPS request:

         GET /?q=1 HTTP/1.1
         Host: www.example.net:8080

       is represented by the base string URI:
       "https://www.example.net:8080/".
    '''
    parsed_url = urlparse(resource_uri)
    scheme = parsed_url.scheme.lower()
    host = parsed_url.netloc.lower()
    port = parsed_url.port
    path = parsed_url.path
    if port == 80 or port == 443:
        base_uri = "%s://%s%s" % (scheme, host, port, path)
    else:
        base_uri = "%s://%s:%s%s" % (scheme, host, port, path)
    return base_uri


def get_parameters(resource_uri,
                   parameters
                   ):
    '''
    3.4.1.3. Request Parameters

       In order to guarantee a consistent and reproducible representation of
       the request parameters, the parameters are collected and decoded to
       their original decoded form.  They are then sorted and encoded in a
       particular manner that is often different from their original
       encoding scheme, and concatenated into a single string.

    3.4.1.3.1. Parameter Sources

       The parameters from the following sources are collected into a single
       list of name/value pairs:

       o  The query component of the HTTP request URI as defined by
          [RFC3986], Section 3.4.  The query component is parsed into a list
          of name/value pairs by treating it as an
          "application/x-www-form-urlencoded" string, separating the names
          and values and decoding them as defined by
          [W3C.REC-html40-19980424], Section 17.13.4.

       o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
          present.  The header's content is parsed into a list of name/value
          pairs excluding the "realm" parameter if present.  The parameter
          values are decoded as defined by Section 3.5.1.

       o  The HTTP request entity-body, but only if all of the following
          conditions are met:

          *  The entity-body is single-part.

          *  The entity-body follows the encoding requirements of the
             "application/x-www-form-urlencoded" content-type as defined by
             [W3C.REC-html40-19980424].

          *  The HTTP request entity-header includes the "Content-Type"
             header field set to "application/x-www-form-urlencoded".

          The entity-body is parsed into a list of decoded name/value pairs
          as described in [W3C.REC-html40-19980424], Section 17.13.4.

       The "oauth_signature" parameter MUST be excluded from the signature
       base string if present.  Parameters not explicitly included in the
       request MUST be excluded from the signature base string (e.g., the
       "oauth_version" parameter when omitted).

       For example, the HTTP request:

           POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
           Host: example.com
           Content-Type: application/x-www-form-urlencoded
           Authorization: OAuth realm="Example",
                          oauth_consumer_key="9djdj82h48djs9d2",
                          oauth_token="kkk9d7dh3k39sjv7",
                          oauth_signature_method="HMAC-SHA1",
                          oauth_timestamp="137131201",
                          oauth_nonce="7d8f3e4a",
                          oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"

           c2&a3=2+q

       contains the following (fully decoded) parameters used in the
       signature base sting:

                   +------------------------+------------------+
                   |          Name          |       Value      |
                   +------------------------+------------------+
                   |           b5           |       =%3D       |
                   |           a3           |         a        |
                   |           c@           |                  |
                   |           a2           |        r b       |
                   |   oauth_consumer_key   | 9djdj82h48djs9d2 |
                   |       oauth_token      | kkk9d7dh3k39sjv7 |
                   | oauth_signature_method |     HMAC-SHA1    |
                   |     oauth_timestamp    |     137131201    |
                   |       oauth_nonce      |     7d8f3e4a     |
                   |           c2           |                  |
                   |           a3           |        2 q       |
                   +------------------------+------------------+

       Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
       "c2" have empty values.  While the encoding rules specified in this
       specification for the purpose of constructing the signature base
       string exclude the use of a "+" character (ASCII code 43) to
       represent an encoded space character (ASCII code 32), this practice
       is widely used in "application/x-www-form-urlencoded" encoded values,
       and MUST be properly decoded, as demonstrated by one of the "a3"
       parameter instances (the "a3" parameter is used twice in this
       request).
    '''
    parameters = {}
    parsed_url = urlparse(resource_uri)
    query_components = {decode_parameter(c[0].split('=')): decode_parameter(c[1].split('='))
                        for c in parsed_url.query.split('&')}
    authorization_header_parameters = parameters
    request_entity_body_parameters = 
    parameters.update(query_components)
    parameters.update(authorization_header_parameters)
    parameters.update(request_entity_body_parameters)
    try:
        del parameters['oauth_signature']
    except:
        pass

    '''
    3.4.1.3.2. Parameters Normalization

       The parameters collected in Section 3.4.1.3 are normalized into a
       single string as follows:

       1.  First, the name and value of each parameter are encoded
           (Section 3.6).

       2.  The parameters are sorted by name, using ascending byte value
           ordering.  If two or more parameters share the same name, they
           are sorted by their value.

       3.  The name of each parameter is concatenated to its corresponding
           value using an "=" character (ASCII code 61) as a separator, even
           if the value is empty.

       4.  The sorted name/value pairs are concatenated together into a
           single string by using an "&" character (ASCII code 38) as
           separator.

       For example, the list of parameters from the previous section would
       be normalized as follows:

                                     Encoded:

                   +------------------------+------------------+
                   |          Name          |       Value      |
                   +------------------------+------------------+
                   |           b5           |     %3D%253D     |
                   |           a3           |         a        |
                   |          c%40          |                  |
                   |           a2           |       r%20b      |
                   |   oauth_consumer_key   | 9djdj82h48djs9d2 |
                   |       oauth_token      | kkk9d7dh3k39sjv7 |
                   | oauth_signature_method |     HMAC-SHA1    |
                   |     oauth_timestamp    |     137131201    |
                   |       oauth_nonce      |     7d8f3e4a     |
                   |           c2           |                  |
                   |           a3           |       2%20q      |
                   +------------------------+------------------+

                                      Sorted:

                   +------------------------+------------------+
                   |          Name          |       Value      |
                   +------------------------+------------------+
                   |           a2           |       r%20b      |
                   |           a3           |       2%20q      |
                   |           a3           |         a        |
                   |           b5           |     %3D%253D     |
                   |          c%40          |                  |
                   |           c2           |                  |
                   |   oauth_consumer_key   | 9djdj82h48djs9d2 |
                   |       oauth_nonce      |     7d8f3e4a     |
                   | oauth_signature_method |     HMAC-SHA1    |
                   |     oauth_timestamp    |     137131201    |
                   |       oauth_token      | kkk9d7dh3k39sjv7 |
                   +------------------------+------------------+

                                Concatenated Pairs:

                      +-------------------------------------+
                      |              Name=Value             |
                      +-------------------------------------+
                      |               a2=r%20b              |
                      |               a3=2%20q              |
                      |                 a3=a                |
                      |             b5=%3D%253D             |
                      |                c%40=                |
                      |                 c2=                 |
                      | oauth_consumer_key=9djdj82h48djs9d2 |
                      |         oauth_nonce=7d8f3e4a        |
                      |   oauth_signature_method=HMAC-SHA1  |
                      |      oauth_timestamp=137131201      |
                      |     oauth_token=kkk9d7dh3k39sjv7    |
                      +-------------------------------------+

       and concatenated together into a single string (line breaks are for
       display purposes only):

         a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
         dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
         &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7

    '''
    parameters = {encode_parameter(k): encode_oauth(v) for k, v in parameters.iteritems()}
    sorted(parameters)
    return ', '.join('%s=%s' % (k, v) for k, v in d.iteritems())


def sign_request(resource_uri, ):
    signature_base_string = get_base_string()
    if hmac_sha1:
        return hmac_sha1(signature_base_string)
    else:
        return sign_rsa_sha1()
    parameters['oauth_signature'] = oauth_signature

def verify_signature():
    signature_base_string = get_base_string()
    if hmac_sha1:
        return hmac_sha1(signature_base_string)
    else:
        return sign_rsa_sha1()


    .get_full_path() uri
   HttpRequest.method method
   HttpRequest.GET request_paramentes
   HttpRequest.body body
   HttpRequest.META.get('HTTP_AUTHORIZATION').replace('OAuth', '') authorize header


class AuthenticatedRespose():
    def __init__(self):
        self.method = method
        self.body = body
        self.META

