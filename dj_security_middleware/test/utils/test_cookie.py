"""
Tests for the cookie module
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


from crypto_cookie.auth_tkt import SecureCookie

from dj_security_middleware.test import BaseMiddlewareTestCase
from dj_security_middleware.utils.cookie import SHARED_SECRET, \
    parse_cookie_value


class TestParseSecureCookie(BaseMiddlewareTestCase):
    
    def test_invalid_cookie(self):
        
        # Error expected when parsing an invalid cookie
        self.assertRaises(Exception, parse_cookie_value, 'invalid')
    
    def test_valid_cookie(self):
        
        cookie = SecureCookie(SHARED_SECRET, 'test', None)
        cookie_value = parse_cookie_value(cookie.cookie_value())
        
        # Parsed cookie should be a tuple
        self.assertTrue(isinstance(cookie_value, tuple),
            "Cookie value is not a tuple.")
