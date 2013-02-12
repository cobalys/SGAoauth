'''
'''
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    args = ''
    help = 'Clear tokens.'

    def handle(self, *args, **options):
        self.stdout.write('Clear tokens.')
        raise NotImplementedError()
