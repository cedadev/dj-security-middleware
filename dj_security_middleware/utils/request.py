"""
Functions for dealing with Django requests.
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


import logging

from django.conf import settings
from django.utils.http import urlencode

from dj_security_middleware.exception import MissingCookieError
from .cookie import parse_cookie_value


log = logging.getLogger(__name__)

DEFAULT_REDIRECT_KEY = 'r'

# URL query parameter keys recognized by middleware.
LOGOUT_KEY = 'logout'
REGISTRATION_KEY = 'registration'


def userid_from_request(request):
    """Gets the value of openid from the relevant cookie.
    
    :param request: The HTTP request object.
    :returns: The parsed value of openid or None.
    :raises: MissingCookieError, CookieParsingError
    """
    
    cookie_name = settings.ACCOUNT_COOKIE_NAME
    if cookie_name in request.COOKIES:
        return parse_cookie_value(request.COOKIES[cookie_name], 1)
    else:
        raise MissingCookieError(
            "No cookie named {0} in request".format(cookie_name))


def openid_from_request(request):
    """Gets the value of userid from the relevant cookie.
    
    :param request: The HTTP request object.
    :returns: The parsed value of userid or None.
    :raises: MissingCookieError, CookieParsingError
    """
    
    if hasattr(settings, 'OPENID_COOKIE_NAME'):
        
        cookie_name = settings.OPENID_COOKIE_NAME
        if cookie_name in request.COOKIES:
            return parse_cookie_value(request.COOKIES[cookie_name], 1)
        else:
            raise MissingCookieError(
                "No cookie named {0} in request".format(cookie_name))
        
    else:
        log.warn("Can't get OpenID without OPENID_COOKIE_NAME setting.")


def login_url(request, redirect=True):
    """Construct a login URL pointing to the configured login service.
    This will contain the current absolute URI of the request as an
    encoded query string parameter which the login service should
    return to after authentication.
    
    :param request: The HTTP request object.
    :param redirect_key: The key used for the redirect parameter.
    """
    
    login_service = settings.SECURITY_LOGIN_SERVICE
    if redirect:
        redirect_key = getattr(
            settings, 'REDIRECT_FIELD_NAME', DEFAULT_REDIRECT_KEY)
        
        query = {redirect_key: request.build_absolute_uri()}
        return '{login_service}?{query}'.format(
            login_service=login_service,
            query=urlencode(query)
        )
        
    else:
        return login_service


def logout_url(request):
    """Returns the full path of the request with an additional logout
    parameter added to the query string. This can be intercepted by
    dj-security-middleware to perform a logout.
    
    :param request: The HTTP request object.
    :returns: A logout URL path.
    """
    
    query = request.GET.copy()
    query[LOGOUT_KEY] = None
    
    logout_path = '{path}?{query}'.format(
        path=request.path, query=urlencode(query))
    return logout_path
