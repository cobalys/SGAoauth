from django.http import HttpResponse
from django.template.context import RequestContext
from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt
from sga_oauth.server.decorator import oauth_service
from sga_oauth.shared.persistence.models import ConsumerToken
import datetime
import json


#Protected Resource
@csrf_exempt
@oauth_service
def get_provider_time(request):
    response_data = {}
    response_data['provider_time'] = datetime.datetime.now().strftime('%I:%M%p')
    return HttpResponse(json.dumps(response_data), mimetype="application/json")


def index(request):
    context = {}
    context['metatag_title'] = "Shared Gov Apps - Admin"
    consumer_tokens = ConsumerToken.objects.all()
    template_name = 'index.html'
    t = get_template(template_name)
    context['consumer_tokens'] = consumer_tokens
    html = t.render(RequestContext(request, context))
    return HttpResponse(html)
