from django.conf.urls import patterns, include, url
from oauthserver.views import get_provider_time, index
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', index, name='index'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name':'login.html',}),
    url(r'^get_provider_time/$', get_provider_time, name='get_provider_time'),
    url(r'^oauthserver/', include('sga_oauth.server.urls')),
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
