from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from sga_oauth.server.views import grant_access_token, grant_request_token, \
    grant_user_authorization


urlpatterns = patterns('',
    url(r'^access$', grant_access_token, name='oauth_access$',),
    url(r'^request$', grant_request_token, name='oauth_request',),
    url(r'^authorization$', grant_user_authorization, name='oauth_authorization',),
)
