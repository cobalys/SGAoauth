'''
Created on Nov 26, 2012

@author: sergio
'''
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from optparse import make_option
from sqlalchemy.engine import create_engine
import psycopg2
import re


class Command(BaseCommand):
    args = ''
    help = 'Migrates the database'

    option_list = BaseCommand.option_list + (
        make_option('--database_password',
            help='Database Password'),
        make_option('--database_name',
            help='Database Name'),
        )

    def handle(self, *args, **options):
        database_password = options['database_password']
        database_name = options['database_name']
        engine = create_engine('postgresql+psycopg2://postgres:%s@' % database_password)
        c = engine.connect()
        engine.raw_connection().set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        try:
            engine.text("CREATE DATABASE %s ENCODING = 'utf8'" % database_name).execute()
        except:
            pass

        engine = create_engine('postgresql+psycopg2://postgres:%s@/%s' % (database_password, database_name))
        engine.raw_connection().set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

#        engine.text("CREATE SCHEMA suggestion").execute()
#        engine.text("CREATE SCHEMA contact_information;").execute()
#        engine.text("CREATE SCHEMA world_division;").execute()
#        engine.text("CREATE SCHEMA taxonomy;").execute()
#        engine.text("CREATE SCHEMA localization;").execute()
#        engine.text("CREATE SCHEMA person;").execute()
#        engine.text("CREATE SCHEMA users_reputation;").execute()
#        engine.text("CREATE SCHEMA organization;").execute()
#        engine.text("CREATE SCHEMA proposal;").execute()
#        engine.text("CREATE SCHEMA project;").execute()
#        engine.text("CREATE SCHEMA organization;").execute()
        engine = create_engine('postgresql+psycopg2://postgres:%s@/%s' % (database_password, database_name))
        p = re.compile(r'schema "(?P<schema_name>\w+)" does not exist')

        while True:
            try:
                settings.BASE.metadata.create_all(engine)
                break
            except Exception, e:
                schema_creation = p.search(str(e))
                if schema_creation:
                    engine.text("CREATE SCHEMA %s;" % schema_creation.group('schema_name')).execute()
                else:
                    break

        self.stdout.write('Schema creation success')













