import time
from django.db import connection
from django.db.utils import OperationalError
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Waits for database to be available'

    def handle(self, *args, **options):
        self.stdout.write('Waiting for database...')
        db_conn = None
        max_tries = 60  # Maximum number of attempts
        attempt = 0

        while attempt < max_tries:
            try:
                connection.ensure_connection()
                db_conn = True
                break
            except OperationalError:
                self.stdout.write(f'Database unavailable, waiting 1 second... (attempt {attempt + 1}/{max_tries})')
                time.sleep(1)
                attempt += 1

        if db_conn:
            self.stdout.write(self.style.SUCCESS('Database available!')) 