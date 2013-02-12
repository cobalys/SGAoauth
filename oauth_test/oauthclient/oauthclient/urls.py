from django.conf.urls import patterns, include, url
from oauthclient.views import index, get_provider_time
from django.contrib import admin

admin.autodiscover()
urlpatterns = patterns('',
    url(r'^access_protected_resource$', get_provider_time, name='access_protected_resource'),
    url(r'^$', index, name='index'),
    url(r'^oauthclient/', include('sga_oauth.client.urls')),
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
