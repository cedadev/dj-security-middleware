"""
Module containing exceptions related to the operation of the middleware.
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


class DJMiddlewareException(Exception):
    """Base exceptions for DJSecurityMiddleware operations."""
    
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value


class CookieParsingError(DJMiddlewareException):
    """Raised when there is a problem parsing the cookie."""
    pass


class MissingCookieError(DJMiddlewareException):
    """Occurs when a required cookie is missing from a request."""
    pass
