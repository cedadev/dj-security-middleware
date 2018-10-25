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

from dj_security_middleware.exception import MissingCookieError
from .cookie import parse_cookie_value


log = logging.getLogger(__name__)


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
