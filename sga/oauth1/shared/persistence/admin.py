from django.contrib import admin
from sga_oauth.shared.persistence.models import Nonce, ConsumerToken, \
    RequestToken, AccessToken


class NonceAdmin(admin.ModelAdmin):
    pass


class ConsumerTokenAdmin(admin.ModelAdmin):
    pass


class RequestTokenAdmin(admin.ModelAdmin):
    pass


class AccessTokenAdmin(admin.ModelAdmin):
    pass


admin.site.register(Nonce, NonceAdmin)
admin.site.register(ConsumerToken, ConsumerTokenAdmin)
admin.site.register(RequestToken, RequestTokenAdmin)
admin.site.register(AccessToken, AccessTokenAdmin)