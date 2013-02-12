from django.conf import settings
from urlparse import urljoin

OAUTH_CONSUMER_KEY = getattr(settings, 'SGA_OAUTH_CONSUMER_KEY')
OAUTH_CONSUMER_SECRET = getattr(settings, 'SGA_OAUTH_CONSUMER_SECRET')

OAUTH_URL = getattr(settings, 'SGA_OAUTH_URL')
OAUTH_PORT = getattr(settings, 'SGA_OAUTH_PORT', 80)

#########
# PATHS
#########
#'/oauth/request'
OAUTH_REQUEST_TOKEN_PATH = getattr(settings, 'SGA_OAUTH_REQUEST_TOKEN_PATH',
                                   '/oauth/request')
OAUTH_REQUEST_TOKEN_URL = urljoin('http://%s:%s' % (OAUTH_URL, OAUTH_PORT),
                                  OAUTH_URL, OAUTH_REQUEST_TOKEN_PATH)

#'/authorization?oauth_token=%s'
OAUTH_REQUEST_TOKEN_AUTHORIZATION_PATH = 
                getattr(settings,
                        'SGA_OAUTH_REQUEST_TOKEN_AUTHORIZATION_URL',
                        '/oauth/authorization?oauth_token=%s')
OAUTH_REQUEST_TOKEN_AUTHORIZATION_URL = urljoin('http://%s:%s' % 
                                        (OAUTH_URL, OAUTH_PORT), 
                                        OAUTH_REQUEST_TOKEN_AUTHORIZATION_PATH)

#'/oauth/access/'
OAUTH_ACCESS_TOKEN_PATH = getattr(settings, 
                                  'SGA_OAUTH_ACCESS_TOKEN_PATH', 
                                  '/oauth/access')
OAUTH_ACCESS_TOKEN_URL = urljoin('http://%s:%s' % (OAUTH_URL, OAUTH_PORT), 
                                 OAUTH_URL, 
                                 OAUTH_ACCESS_TOKEN_PATH)

#'http://www.engagementsquared.com/sso/callback'
OAUTH_CALLBACK_URL = getattr(settings, 'SGA_OAUTH_CALLBACK_URL')
OAUTH_LOGOUT_URL = getattr(settings, 'SGA_OAUTH_LOGOUT_URL')
