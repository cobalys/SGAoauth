'''
Created on Nov 26, 2012
@author: sergio
'''
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from optparse import make_option
from sga_oauth.shared.persistence.models import ConsumerToken
from sqlalchemy.engine import create_engine, create_engine
from sqlalchemy.ext.declarative import declarative_base
import psycopg2
import re
import sqlalchemy


class Command(BaseCommand):
    args = ''
    help = 'Creates a superuser'

#    option_list = BaseCommand.option_list + (
#        make_option('--database_password',
#            help='Database Password'),
#        make_option('--database_name',
#            help='Database Name'),
#        make_option('--superuser_password',
#            help='Database Password'),
#        make_option('--superuser_name',
#            help='Database Name'),
#        )


    def handle(self, *args, **options):
#        ENGINE = create_engine('postgresql://postgres:alf785bad@localhost/sga')
#        BASE = declarative_base()
#        SESSION = sqlalchemy.orm.sessionmaker(bind=ENGINE, expire_on_commit=False)
        consumer_token = ConsumerToken()
        consumer_token.client_name = 'Test'
        consumer_token.generate_tokens()
        consumer_token.save()
#        session = SESSION()
#        session.add(person)
#        session.commit()
#        session.refresh(person)
#                    oauth_key
        self.stdout.write('Superuser creation success')

