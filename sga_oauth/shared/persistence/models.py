from django.contrib.auth.models import User
from django.db import models
from sga_oauth.shared.helpers.generators import make_random


class Nonce(models.Model):
    nonce_id = models.AutoField(primary_key=True)
    nounce_key = models.CharField(max_length=255)
    datetime_created = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return u"Nonce %s" % self.nounce_key


class Token(models.Model):
    oauth_key = models.CharField(max_length=200, null=True, blank=True)
    oauth_secret = models.CharField(max_length=200, null=True, blank=True)
    timastamp_created = models.DateTimeField(auto_now_add=True)
    verifier = models.CharField(max_length=200, null=True, blank=True)

    def generate_tokens(self, *args, **kwargs):
        self.oauth_key = make_random()
        self.oauth_secret = make_random()
        super(Token, self).save(*args, **kwargs)

    class Meta:
        abstract = True


class ConsumerToken(Token):
    consumer_token_id = models.AutoField(primary_key=True)
    client_name = models.CharField(max_length=200, null=True, blank=True)
    client_url = models.URLField(max_length=200, null=True, blank=True)


class RequestToken(Token):
    request_token_id = models.AutoField(primary_key=True)
    consumer = models.ForeignKey(ConsumerToken)
    callback = models.URLField(max_length=200)
    is_approved = models.BooleanField(default=False)


class AccessToken(Token):
    access_token_id = models.AutoField(primary_key=True)
    consumer = models.ForeignKey(ConsumerToken)

