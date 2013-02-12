'''
'''
from django.core.management.base import BaseCommand
from sga_oauth.shared.persistence.models import ConsumerToken


class Command(BaseCommand):
    args = ''
    help = 'Creates a consumer token.'

    def handle(self, *args, **options):
        consumer_token = ConsumerToken()
        consumer_token.client_name = 'Test'
        consumer_token.generate_tokens()
        consumer_token.save()
        self.stdout.write('Consumer token creation done.')
