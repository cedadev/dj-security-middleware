"""
Package for dj_security_middleware tests.
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


import os
import codecs

secret = codecs.encode(os.urandom(32), 'base64').decode().strip()

from django.test import SimpleTestCase, RequestFactory
from django.utils.http import urlencode
from django.conf import settings
if not settings.configured:
    settings.configure(
        ACCOUNT_COOKIE_NAME='account',
        SECURITY_LOGIN_SERVICE='http://localhost/signin/',
        SECURITY_SHAREDSECRET=secret,
        ALLOWED_HOSTS=['*'],
    )

from dj_security_middleware.utils.request import DEFAULT_REDIRECT_KEY


class BaseMiddlewareTestCase(SimpleTestCase):
    
    TEST_HOST = 'testserver'
    TEST_URL = 'http://{host}/'.format(host=TEST_HOST)
    
    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get('/')
        self.request.session = {}
    
    def _redirect_url(self, redirect_key=None):
        
        if not redirect_key:
            redirect_key = getattr(
                settings, 'REDIRECT_FIELD_NAME', DEFAULT_REDIRECT_KEY)
        query = {redirect_key: self.TEST_URL}
        return '{url}?{query}'.format(
            url=settings.SECURITY_LOGIN_SERVICE, query=urlencode(query))
