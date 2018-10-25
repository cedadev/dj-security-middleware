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

from django.test import SimpleTestCase, RequestFactory
from django.conf import settings
if not settings.configured:
    settings.configure(
        ACCOUNT_COOKIE_NAME='account',
        SECURITY_LOGIN_SERVICE='http://localhost/signin/',
        SECURITY_SHAREDSECRET=codecs.encode(os.urandom(16), 'base64').strip()
    )


class BaseMiddlewareTestCase(SimpleTestCase):
    
    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get('/')
        self.request.session = {}
