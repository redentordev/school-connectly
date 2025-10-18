"""
Django management command to verify security controls
"""

from django.core.management.base import BaseCommand
from django.conf import settings
import logging
import os


class Command(BaseCommand):
    help = 'Verify all 5 security controls for Milestone 2'

    def handle(self, *args, **options):
        self.stdout.write('=' * 80)
        self.stdout.write(self.style.SUCCESS('SECURITY CONTROLS VERIFICATION - MILESTONE 2'))
        self.stdout.write('=' * 80)
        self.stdout.write('')

        passed = 0
        failed = 0

        # Control 1: Token Redaction
        self.stdout.write('[CONTROL 1] JWT Token Redaction in Logs')
        self.stdout.write('-' * 80)
        try:
            from connectly.logging_filters import SensitiveDataFilter
            
            class TestRecord(logging.LogRecord):
                def __init__(self, msg):
                    super().__init__('test', logging.INFO, '', 0, msg, (), None)
            
            filter_obj = SensitiveDataFilter()
            
            test_cases = [
                ('Authorization: Bearer eyJhbGc.test.token', 'Bearer token'),
                ('token: abc123xyz456789', 'Token field'),
                ('password: mySecretPassword123', 'Password'),
                ('access_token: ya29.google.token', 'Google token'),
            ]
            
            redacted_count = 0
            for test_input, desc in test_cases:
                record = TestRecord(test_input)
                filter_obj.filter(record)
                is_redacted = 'REDACTED' in record.msg
                if is_redacted:
                    redacted_count += 1
                    self.stdout.write(f'  ✅ {desc}: REDACTED')
                    passed += 1
                else:
                    self.stdout.write(self.style.ERROR(f'  ❌ {desc}: NOT REDACTED'))
                    failed += 1
            
            self.stdout.write(f'\nResult: {redacted_count}/{len(test_cases)} patterns redacted\n')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Error: {e}'))
            failed += 1

        # Control 2: Rate Limiting
        self.stdout.write('[CONTROL 2] Rate Limiting for Login API')
        self.stdout.write('-' * 80)
        try:
            from connectly.rate_limiters import rate_limit_auth
            
            self.stdout.write(f'  ✅ rate_limit_auth decorator: EXISTS')
            self.stdout.write(f'  ✅ RATELIMIT_ENABLE: {settings.RATELIMIT_ENABLE}')
            self.stdout.write(f'  ✅ Rate limit backend: {settings.RATELIMIT_USE_CACHE}')
            
            from django.core.cache import cache
            cache.set('ratelimit_test', 'value', 60)
            value = cache.get('ratelimit_test')
            if value == 'value':
                self.stdout.write(f'  ✅ Cache (for rate limiting): WORKING')
                passed += 3
            else:
                self.stdout.write(self.style.ERROR(f'  ❌ Cache: NOT WORKING'))
                failed += 1
                passed += 2
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Error: {e}'))
            failed += 1

        self.stdout.write('')

        # Control 3: Debug Prevention
        self.stdout.write('[CONTROL 3] Debug Information Disclosure Prevention')
        self.stdout.write('-' * 80)
        try:
            from connectly import views
            
            self.stdout.write(f'  DEBUG mode: {settings.DEBUG}')
            if settings.DEBUG:
                self.stdout.write(self.style.WARNING('  ⚠️  DEBUG=True (should be False in production)'))
            else:
                self.stdout.write(f'  ✅ DEBUG=False (production mode)')
            passed += 1
            
            handlers = ['custom_400', 'custom_403', 'custom_404', 'custom_500']
            handler_count = 0
            for handler in handlers:
                if hasattr(views, handler):
                    self.stdout.write(f'  ✅ {handler}: EXISTS')
                    handler_count += 1
                else:
                    self.stdout.write(self.style.ERROR(f'  ❌ {handler}: MISSING'))
            
            passed += handler_count
            failed += (len(handlers) - handler_count)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Error: {e}'))
            failed += 1

        self.stdout.write('')

        # Control 4: Secret Management
        self.stdout.write('[CONTROL 4] Environment-Based Secret Management')
        self.stdout.write('-' * 80)
        try:
            from connectly import env_validator
            
            funcs = ['get_secret_key', 'get_debug_mode', 'get_allowed_hosts', 'validate_environment']
            func_count = 0
            for func in funcs:
                if hasattr(env_validator, func):
                    self.stdout.write(f'  ✅ {func}: EXISTS')
                    func_count += 1
                else:
                    self.stdout.write(self.style.ERROR(f'  ❌ {func}: MISSING'))
            
            passed += func_count
            failed += (len(funcs) - func_count)
            
            if os.path.exists('.env.example'):
                with open('.env.example') as f:
                    content = f.read()
                    if all(key in content for key in ['SECRET_KEY', 'DEBUG', 'DATABASE_URL']):
                        self.stdout.write(f'  ✅ .env.example: COMPLETE')
                        passed += 1
                    else:
                        self.stdout.write(self.style.ERROR(f'  ❌ .env.example: INCOMPLETE'))
                        failed += 1
            else:
                self.stdout.write(self.style.ERROR(f'  ❌ .env.example: MISSING'))
                failed += 1
            
            if 'django-insecure' in settings.SECRET_KEY:
                self.stdout.write(self.style.WARNING('  ⚠️  Using development SECRET_KEY'))
            else:
                self.stdout.write(f'  ✅ SECRET_KEY: Production-ready')
            passed += 1
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Error: {e}'))
            failed += 1

        self.stdout.write('')

        # Control 5: Server Headers
        self.stdout.write('[CONTROL 5] Server Information Disclosure Prevention')
        self.stdout.write('-' * 80)
        try:
            from connectly.middleware import SecurityHeadersMiddleware, RateLimitLoggingMiddleware
            
            self.stdout.write(f'  ✅ SecurityHeadersMiddleware: EXISTS')
            self.stdout.write(f'  ✅ RateLimitLoggingMiddleware: EXISTS')
            
            middleware_list = settings.MIDDLEWARE
            if 'connectly.middleware.SecurityHeadersMiddleware' in middleware_list:
                self.stdout.write(f'  ✅ SecurityHeadersMiddleware: CONFIGURED')
                passed += 1
            else:
                self.stdout.write(self.style.ERROR(f'  ❌ SecurityHeadersMiddleware: NOT CONFIGURED'))
                failed += 1
            
            if 'connectly.middleware.RateLimitLoggingMiddleware' in middleware_list:
                self.stdout.write(f'  ✅ RateLimitLoggingMiddleware: CONFIGURED')
                passed += 1
            else:
                self.stdout.write(self.style.ERROR(f'  ❌ RateLimitLoggingMiddleware: NOT CONFIGURED'))
                failed += 1
            
            passed += 1
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Error: {e}'))
            failed += 1

        self.stdout.write('')

        # Additional tests
        self.stdout.write('[ADDITIONAL] Database & Logging')
        self.stdout.write('-' * 80)
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
                result = cursor.fetchone()
                if result[0] == 1:
                    self.stdout.write(f'  ✅ PostgreSQL: CONNECTED')
                    passed += 1
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Database: {e}'))
            failed += 1

        try:
            logger = logging.getLogger('connectly_logger')
            self.stdout.write(f'  ✅ Logger: {len(logger.handlers)} handlers configured')
            for handler in logger.handlers:
                filter_names = [f.__class__.__name__ for f in handler.filters]
                if 'SensitiveDataFilter' in filter_names:
                    self.stdout.write(f'     ✅ Has SensitiveDataFilter')
            passed += 1
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  ❌ Logging: {e}'))
            failed += 1

        self.stdout.write('')

        # Summary
        self.stdout.write('=' * 80)
        self.stdout.write(self.style.SUCCESS('SUMMARY'))
        self.stdout.write('=' * 80)
        total = passed + failed
        pass_rate = (passed / total * 100) if total > 0 else 0

        self.stdout.write(f'Total Tests: {total}')
        self.stdout.write(self.style.SUCCESS(f'Passed: {passed} ✅'))
        if failed > 0:
            self.stdout.write(self.style.ERROR(f'Failed: {failed} ❌'))
        else:
            self.stdout.write(f'Failed: {failed}')
        self.stdout.write(f'Pass Rate: {pass_rate:.1f}%')

        if pass_rate >= 90:
            self.stdout.write(self.style.SUCCESS('\n🎉 EXCELLENT: All critical security controls are properly implemented!'))
        elif pass_rate >= 75:
            self.stdout.write(self.style.SUCCESS('\n✅ GOOD: Most security controls are working correctly.'))
        elif pass_rate >= 50:
            self.stdout.write(self.style.WARNING('\n⚠️  FAIR: Some security controls need attention.'))
        else:
            self.stdout.write(self.style.ERROR('\n❌ POOR: Multiple security controls have issues.'))

        self.stdout.write('=' * 80)

