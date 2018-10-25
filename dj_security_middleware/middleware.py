"""
Django middleware class which intercepts requests and authenticates users if
it detects a valid login cookie.
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


import logging
import re
import socket

from django.conf import settings
from django.utils.http import urlencode
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseRedirect
from six.moves import urllib

from .exception import CookieParsingError
from .utils.cookie import parse_cookie_value
from .utils.request import userid_from_request, openid_from_request


log = logging.getLogger(__name__)


class DJSecurityMiddleware(MiddlewareMixin):
    """Intercepts requests submitted by the underlying Django application and
    either sets up session details for an externally authenticated user or
    performs logout or redirection.
    """
    
    # URL query parameter keys recognized by middleware.
    LOGOUT = 'logout'
    REGISTRATION = 'registration'
    
    # Key in session dictionary used to store the users account ID
    SESSION_KEY = 'accountid'
    
    def __init__(self, *args, **kwargs):
        
        self._login_service = settings.SECURITY_LOGIN_SERVICE
        self._redirect_key = getattr(settings, 'REDIRECT_FIELD_NAME', 'r')
        
        # Retrieve cookie domain from settings or use login service host.
        if hasattr(settings, 'COOKIE_DOMAIN'):
            self._cookie_domain = settings.COOKIE_DOMAIN
        else:
            netloc = urllib.parse.urlparse(self._login_service).netloc
            if netloc.find(':') > 0:
                self._cookie_domain = netloc[:netloc.index(':')]
            else:
                self._cookie_domain = netloc
        
        # Compile a list of all authentication cookie names.
        self._auth_cookie_names = [settings.ACCOUNT_COOKIE_NAME]
        if hasattr(settings, 'OPENID_COOKIE_NAME'):
            self._auth_cookie_names.append(settings.OPENID_COOKIE_NAME)
        
        extra_cookie_names = getattr(settings, 'EXTRA_COOKIE_NAMES', [])
        if isinstance(extra_cookie_names, list):
            self._auth_cookie_names += extra_cookie_names
        else:
            raise ValueError("EXTRA_COOKIE_NAMES must be a list of strings.")
        
        # Compile a list of public URLs
        self._public_urls = []
        if hasattr(settings, 'DJ_SECURITY_FILTER'):
            self._public_urls += [re.compile(expr) for expr in settings.DJ_SECURITY_FILTER]
        
        super(DJSecurityMiddleware, self).__init__(*args, **kwargs)
    
    def process_request(self, request):
        """Verifies the presence of a valid authentication cookie in the
        request object. If found, user details are extracted from the cookie
        and used to construct an authenticated session.
        
        A redirect response is returned if authentication cannot be verified,
        either by the presence of a valid cookie or a positive response from
        custom_auth, or if the requested path is not found in EXEMPT_URLS.
        
        :returns: Redirect response or None
        """
        
        if self.REGISTRATION in request.GET:
            # Redirect to registration URL
            return HttpResponseRedirect('{login_service}?registration'.format(
                login_service=self._login_service))
        
        if self.LOGOUT in request.GET:
            # Redirect to login service
            response = HttpResponseRedirect(self._build_return_to_url(request))
            
            log.debug("Removing cookies {cookies} for {domain}".format(
                cookies=self._auth_cookie_names, domain=self._cookie_domain)
            )
            for cookie_name in self._auth_cookie_names:
                response.delete_cookie(cookie_name, domain=self._cookie_domain)
            
            request.session[self.SESSION_KEY] = None
            return response
        
        # Perform custom authentication, potentially bypassing the middleware
        custom_auth = getattr(settings, 'DJ_SECURITY_AUTH_CHECK', None)
        if custom_auth:
            try:
                if custom_auth(request):
                    return
            except Exception as e:
                log.warn(
                    "Uncaught exception in DJ_SECURITY_AUTH_CHECK function."
                )
                raise e
        
        authenticated = False
        
        # Attempt to locate and read a secure authentication cookie
        account_cookie_name = settings.ACCOUNT_COOKIE_NAME
        if account_cookie_name not in request.COOKIES:
            log.info("Missing cookie {cookie}, redirecting to login".format(
                cookie=account_cookie_name))
        else:
            try:
                timestamp, userid = parse_cookie_value(
                    request.COOKIES[account_cookie_name])[:2]
                
                # Authenticate request
                self._prepare_user_for_session(request, timestamp, userid)
                authenticated = True
                
            except CookieParsingError:
                log.error(
                    "Error authenticating request. Redirecting to login.")
        
        if not authenticated and not self._is_public(request.path_info):
            # Authentication has failed and the URL is not public. Redirect
            # request to the login service.
            query = urlencode({
                self._redirect_key: self._build_return_to_url(request)
            })
            
            url = '{login_service}?{query}'.format(
                login_service=self._login_service,
                query=query
            )
            return HttpResponseRedirect(url)
    
    def _is_public(self, path):
        """Checks a given path against a list of regex patterns.
        
        :param path: The URL path to filter.
        """
        
        path = path.lstrip('/')
        if any(m.match(path) for m in self._public_urls):
            return True
    
    @classmethod
    def _prepare_user_for_session(cls, request, timestamp, userid):
        """Set authenticated session for a user.
        
        :param request: The HTTP request object.
        :param timestamp: timestamp value from the auth cookie.
        :param userid: userid value from the auth cookie.
        """
        
        request.authenticated_user = {
            'timestamp': timestamp,
            'userid': userid,
        }
        log.debug("User stored in request: {userid}".format(userid=userid))
        request.session[cls.SESSION_KEY] = userid
    
    @classmethod
    def _build_return_to_url(cls, request):
        """Construct a URL encoded string containing the URL which the login
        service should return to after authentication.
        
        :param request: The HTTP request object.
        """
        
        hostname = request.environ.get('HTTP_HOST', socket.getfqdn())
        new_get = request.GET.copy()
        
        # Removed the LOGOUT request attribute
        new_get.pop(cls.LOGOUT, None)
        
        url = 'http://{host}{path}'
        get_values = urllib.parse.urlencode(new_get)
        if len(get_values) > 0:
            url = 'http://{host}{path}?{get}'
            
        return url.format(host=hostname,
                          path=request.path,
                          get=get_values)


def DJ_Security_Middleware(*args, **kwargs):
    
    from warnings import warn
    warn(("The name DJ_Security_Middleware has been deprecated. "
        "Use DJSecurityMiddleware, instead."))
    return DJSecurityMiddleware(*args, **kwargs)


def get_userid_from_request(request):
    
    from warnings import warn
    warn(("This function has been deprecated. Use "
        "dj_security_middleware.utils.userid_from_request, instead."))
    
    try:
        return userid_from_request(request)
    except:
        return None


def get_openid_from_request(request):
    
    from warnings import warn
    warn(("This function has been deprecated. Use "
        "dj_security_middleware.utils.openid_from_request, instead."))
    
    try:
        return openid_from_request(request)
    except:
        return None
