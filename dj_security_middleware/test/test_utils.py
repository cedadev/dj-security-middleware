"""
Tests for the utils module
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


from crypto_cookie.auth_tkt import SecureCookie
from django.test import override_settings

from dj_security_middleware.exception import MissingCookieError
from dj_security_middleware.utils.cookie import SHARED_SECRET, \
    parse_cookie_value
from dj_security_middleware.utils.request import userid_from_request, \
    openid_from_request

from . import settings, BaseMiddlewareTestCase


class TestUseridFromRequest(BaseMiddlewareTestCase):
    
    def test_no_cookie(self):
        
        # Missing cookie so exception should be raised
        self.assertRaises(
            MissingCookieError, userid_from_request, self.request)
    
    def test_valid_cookie(self):
        
        userid = 'test'
        account_cookie = SecureCookie(SHARED_SECRET, userid, None)
        self.request.COOKIES = {
            settings.ACCOUNT_COOKIE_NAME: account_cookie.cookie_value()
        }
        
        # Expect the userid to be parsed successfully
        self.assertEqual(userid_from_request(self.request), userid)


class TestOpenidFromRequest(BaseMiddlewareTestCase):
    
    def test_missing_cookie_name_setting(self):
        
        # None should be returned since the cookie name has not been set
        self.assertEqual(openid_from_request(self.request), None)
    
    @override_settings(OPENID_COOKIE_NAME='openid')
    def test_no_cookie(self):
        
        # Missing cookie so exception should be raised
        self.assertRaises(
            MissingCookieError, openid_from_request, self.request)
    
    @override_settings(OPENID_COOKIE_NAME='openid')
    def test_valid_cookie(self):
        
        openid = 'test'
        openid_cookie = SecureCookie(SHARED_SECRET, openid, None)
        self.request.COOKIES = {
            settings.OPENID_COOKIE_NAME: openid_cookie.cookie_value()
        }
        
        # Expect the openid to be parsed successfully
        self.assertEqual(openid_from_request(self.request), openid)


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
