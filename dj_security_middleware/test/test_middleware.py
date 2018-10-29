"""
Tests for the middleware module
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


from crypto_cookie.auth_tkt import SecureCookie
from django.test import override_settings
from six import itervalues

from dj_security_middleware.utils.cookie import SHARED_SECRET
from dj_security_middleware.utils.request import LOGOUT_KEY
from dj_security_middleware.middleware import DJSecurityMiddleware, \
    get_userid_from_request, get_openid_from_request

from . import settings, BaseMiddlewareTestCase


class TestDJSecurityMiddleware(BaseMiddlewareTestCase):
    """Unit tests for DJSecurityMiddleware methods
    """
    
    def setUp(self):
        
        super(TestDJSecurityMiddleware, self).setUp()
        self.middleware = DJSecurityMiddleware()
    
    def test_anonymous_user(self):
        
        response = self._get_response('/')
        
        # Check for authentication redirect
        self.assertEqual(response.status_code, 302)
    
    def test_redirect(self):
        
        response = self._get_response('/')
        
        # Check for correct redirect URL
        self.assertEqual(response.url, self._redirect_url())
    
    def test_authenticated_user(self):
        
        userid = 'test'
        account_cookie = SecureCookie(SHARED_SECRET, userid, None)
        cookies = {
            settings.ACCOUNT_COOKIE_NAME: account_cookie.cookie_value()
        }
        
        request = self.factory.get('/')
        request.session = {}
        request.COOKIES = cookies
        response = self.middleware.process_request(request)
        
        # Check that request passes middleware
        self.assertIsNone(response)
        
        # Check for userid in session
        self.assertEqual(
            request.session[DJSecurityMiddleware.SESSION_KEY], userid)
    
    def test_logout(self):
        
        logout_path = '/?{}'.format(LOGOUT_KEY)
        
        # Expect redirect after logout
        self.assertEqual(self._get_response(logout_path).status_code, 302)
    
    def test_logout_remove_account_cookie(self):
        
        cookie_name = settings.ACCOUNT_COOKIE_NAME
        
        logout_path = '/?{}'.format(LOGOUT_KEY)
        response = self._get_response(logout_path)
        
        # Check for expected number of cookies
        self.assertEqual(len(response.cookies), 1)
        account_cookie = next(itervalues(response.cookies))
        
        # Check that the cookie has the correct name
        self.assertEquals(account_cookie.key, cookie_name)
        
        # Check that the cookie has been removed
        self.assertTrue('1970' in account_cookie['expires'])
    
    @override_settings(OPENID_COOKIE_NAME='openid',
        EXTRA_COOKIE_NAMES=['extra'])
    def test_logout_with_all_cookies(self):
        
        cookie_names = [
            settings.ACCOUNT_COOKIE_NAME,
            settings.OPENID_COOKIE_NAME
        ] + settings.EXTRA_COOKIE_NAMES
        
        logout_path = '/?{}'.format(LOGOUT_KEY)
        response = self._get_response(logout_path, True)
        
        # Check for expected number of cookies
        self.assertEqual(len(response.cookies), 3)
        
        for cookie in itervalues(response.cookies):
            
            # Check that the cookie matches one in the list
            self.assertTrue(cookie.key in cookie_names)
            
            # Check that the cookie has been removed
            self.assertTrue('1970' in cookie['expires'])
    
    @override_settings(DJ_SECURITY_FILTER=['.*'])
    def test_filter_all(self):
        
        # All paths should be ignored by the middleware
        self.assertIsNone(self._get_response('/some/path/', True))
    
    @override_settings(DJ_SECURITY_FILTER=['^$'])
    def test_filter_root(self):
        
        # Base path should be ignored
        ignored_response = self._get_response('/', True)
        self.assertIsNone(ignored_response)
        
        # Other paths should be restricted
        redirected_response = self._get_response('/restricted/', True)
        self.assertEqual(redirected_response.status_code, 302)
    
    @override_settings(DJ_SECURITY_FILTER=['public/'])
    def test_filter_path(self):
        
        # Filtered path should be ignored
        ignored_response = self._get_response('/public/', True)
        self.assertIsNone(ignored_response)
        
        # Other paths should be restricted
        redirected_response = self._get_response('/restricted/', True)
        self.assertEqual(redirected_response.status_code, 302)
    
    def _create_request(self, path, cookies={}):
        """ Utility method for tests. """
        
        request = self.factory.get(path)
        request.session = {}
        request.cookies = cookies
        request.environ['HTTP_HOST'] = self.TEST_HOST
        
        return request
    
    def _get_response(self, path, new_middleware=False, cookies={}):
        """ Utility method for tests. """
        
        request = self._create_request(path, cookies=cookies)
        
        if new_middleware:
            middleware = DJSecurityMiddleware()
            return middleware.process_request(request)
        else:
            return self.middleware.process_request(request)


class TestGetUseridFromRequest(BaseMiddlewareTestCase):
    
    def test_no_cookie(self):
        
        # Expect the userid to be parsed successfully
        self.assertEqual(get_userid_from_request(self.request), None)


class TestGetOpenidFromRequest(BaseMiddlewareTestCase):
    
    def test_no_cookie(self):
        
        # Expect the openid to be parsed successfully
        self.assertEqual(get_openid_from_request(self.request), None)
