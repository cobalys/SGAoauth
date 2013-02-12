'''
SGAOAUTH Settings
'''

'''
SGAOAUTH_IMPLEMENTATIONS: This is the dictionary with the configuration for
acccess all the Oauth providers avalaibles for this application.
'''
IMPLEMENTATION_TEST = {
    'NAMESPACE': 'test',
    'OAUTH_URL': '127.0.0.1',
    'OAUTH_REQUEST_TOKEN_PATH': '/oauthserver/request',
    'OAUTH_AUTHORIZATION_REQUEST_TOKEN_PATH': '/oauthserver/authorization?oauth_token=%s',
    'OAUTH_ACCESS_TOKEN_PATH': '/oauthserver/access',
    'OAUTH_PORT': '8001',
    'OAUTH_CONSUMER_KEY': '',
    'OAUTH_CONSUMER_SECRET': '',
    'OAUTH_CALLBACK_URL': 'http://127.0.0.1:8000/oauthclient/callback/test/?oauth_token=%s&oauth_verifier=%s',
    'METHODS': {
                'get_provider_time':'/get_provider_time/',
                }
}

SGAOAUTH_IMPLEMENTATIONS = {
                            'test': IMPLEMENTATION_TEST,
                            }
