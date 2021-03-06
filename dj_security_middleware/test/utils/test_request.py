"""
Tests for the request module
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


from crypto_cookie.auth_tkt import SecureCookie
from django.test import override_settings

from dj_security_middleware.test import settings, BaseMiddlewareTestCase
from dj_security_middleware.exception import MissingCookieError
from dj_security_middleware.utils.cookie import SHARED_SECRET
from dj_security_middleware.utils.request import LOGOUT_KEY, \
    userid_from_request, openid_from_request, login_url, logout_url


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


class TestLoginUrl(BaseMiddlewareTestCase):
    
    def test_with_redirect(self):
        
        # Expecting login URL with redirect
        expected_url = self._redirect_url()
        self.assertEqual(login_url(self.request), expected_url)
    
    def test_without_redirect(self):
        
        # Expecting login URL without redirect
        expected_url = settings.SECURITY_LOGIN_SERVICE
        self.assertEqual(login_url(self.request, redirect=False), expected_url)
    
    @override_settings(REDIRECT_FIELD_NAME='test')
    def test_alternate_redirect_key(self):
        
        # Expecting login URL with redirect and unique key
        expected_url = self._redirect_url(redirect_key='test')
        self.assertEqual(login_url(self.request), expected_url)


class TestLogoutUrl(BaseMiddlewareTestCase):
    
    def test_basic_path(self):
        
        url = logout_url(self.factory.get('/'))
        keys = [param.split('=')[0] for param in url.split('?')[1].split('&')]
        
        # Returned path should contain an extra query parameter
        self.assertIn(LOGOUT_KEY, keys)
    
    def test_path_with_query(self):
        
        url = logout_url(self.factory.get('/?test=value'))
        keys = [param.split('=')[0] for param in url.split('?')[1].split('&')]
        
        # Returned path should contain an extra query parameter
        self.assertIn('test', keys)
        self.assertIn(LOGOUT_KEY, keys)
