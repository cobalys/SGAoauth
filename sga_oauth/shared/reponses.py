from django.http import HttpResponse
from urllib import urlencode

'''
10.  HTTP Response Codes

    This section applies only to the Request Token and Access Token requests.
    In general, the Service Provider SHOULD use the response codes defined in
    [RFC2616] Section 10. When the Service Provider rejects a Consumer request,
    it SHOULD respond with HTTP 400 Bad Request or HTTP 401 Unauthorized.

    HTTP 400 Bad Request
        Unsupported parameter
        Unsupported signature method
        Missing required parameter
        Duplicated OAuth Protocol Parameter
    HTTP 401 Unauthorized
        Invalid Consumer Key
        Invalid / expired Token
        Invalid signature
        Invalid / used nonce
'''


class HttpUnsupportedParameter(HttpResponse):
    status_code = 400

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
                'error': 'Unsupported Parameter',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpUnsupportedSignatureMethod(HttpResponse):
    status_code = 400

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Unsupported signature method',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpMissingRequiredParameter(HttpResponse):
    status_code = 400

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Missing required parameter',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpDuplicatedOAuthProtocolParameter(HttpResponse):
    status_code = 400

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Duplicated OAuth Protocol Parameter',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpInvalidConsumerKey(HttpResponse):
    status_code = 401

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Invalid Consumer Key',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpInvalidExpiredToken(HttpResponse):
    status_code = 401

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Invalid / expired Token',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpInvalidSignature(HttpResponse):
    status_code = 401

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Invalid signature',
            })
        self.content_type = 'application/x-www-form-urlencoded'


class HttpInvalidUsedNonce(HttpResponse):
    status_code = 401

    def __init__(self):
        super(HttpInvalidExpiredToken, self).__init__()
        self.content = urlencode({
               'error': 'Invalid / used nonce',
            })
        self.content_type = 'application/x-www-form-urlencoded'
