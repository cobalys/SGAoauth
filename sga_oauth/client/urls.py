from django.conf.urls import patterns, include, url
from sga_oauth.client.views import obtain_request_token, callback


urlpatterns = patterns('',
    url(r'^obtain_request_token/(?P<namespace>\w+)/', obtain_request_token, name='sga_oauth_obtain_request_token',),
    url(r'^callback/(?P<namespace>\w+)/', callback, name='sga_oauth_callback',),
)

