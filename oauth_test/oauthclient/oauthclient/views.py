from django.conf import settings
from django.http import HttpResponse
from django.template.context import RequestContext
from django.template.loader import get_template
from sga_oauth.client.oauth_client import OauthClient
import json


def index(request):
    template_name = 'index.html'
    t = get_template(template_name)
    html = t.render(RequestContext(request, {}))
    return HttpResponse(html)


def get_provider_time(request):
    template_name = 'resource.html'
    oauth_test_server = OauthClient(settings=settings.SGAOAUTH_IMPLEMENTATIONS['test'],
                                    session=request.session)
    try:
        result = oauth_test_server.method('get_provider_time')
    except Exception, e:
        return oauth_test_server.get_tokens()
    t = get_template(template_name)
    provider_time = json.loads(result)['provider_time']
    html = t.render(RequestContext(request, {'provider_time': provider_time, }))
    return HttpResponse(html)

