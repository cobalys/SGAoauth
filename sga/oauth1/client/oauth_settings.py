from django.conf import settings

IMPLEMENTATIONS = getattr(settings, 'SGAOAUTH_IMPLEMENTATIONS', ())

'''
    Example implementation of SGAOAUTH_IMPLEMENTATIONS
'''
IMPLEMENTATION_TEST = {
    'OAUTH_URL': 'http://',
    'OAUTH_REQUEST_TOKEN_PATH': '/oauth/request',
    'OAUTH_AUTHORIZATION_REQUEST_TOKEN_PATH': '/oauth/request',
    'OAUTH_ACCESS_TOKEN_PATH': '/oauth/access',
    'OAUTH_PORT': 8000,
    'OAUTH_CONSUMER_KEY': '',
    'OAUTH_CONSUMER_SECRET': '',
    'OAUTH_CALLBACK_URL': '',
}

SGAOAUTH_IMPLEMENTATIONS = (
                                IMPLEMENTATION_TEST
                            )
