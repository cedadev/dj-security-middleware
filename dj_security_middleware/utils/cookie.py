"""
Cooking parsing functions.
"""

__author__ = "Maurizio Nagni (STFC)"
__maintainer__ = "William Tucker (STFC)"
__date__ = "2012-10-02"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level package"
__contact__ = "william.tucker@stfc.ac.uk"


import codecs
import logging

from crypto_cookie.exceptions import BadTicket
from crypto_cookie.auth_tkt import SecureCookie
from crypto_cookie.signature import VerificationError
from django.conf import settings

from dj_security_middleware.exception import CookieParsingError


log = logging.getLogger(__name__)

SHARED_SECRET = codecs.decode(
    settings.SECURITY_SHAREDSECRET.encode(), 'base64')


def parse_cookie_value(cookie_value, index=None):
    """Verifies the presence and validity of a secure paste cookie.
    If the cookie is present then the decrypted content is returned.
    
    :param cookie: An instance of SecureCookie.
    :param index: Index of a desired value from the cookie.
    :returns: The parsed cookie (a tuple) or the value at index.
    :raises: CookieParsingError
    """
    
    try:
        parsed_cookie_items = SecureCookie.parse_ticket(
            SHARED_SECRET,
            cookie_value,
            None,
            None)
        if index is not None:
            return parsed_cookie_items[index]
        else:
            return parsed_cookie_items
    
    except BadTicket as e:
        log.warn("Error decoding cookie.")
        raise CookieParsingError(e)
    except VerificationError as e:
        log.warn("Cookie signature verification error.")
        raise CookieParsingError(e)
    except IndexError:
        log.warn("Index not in cookie.")
        raise CookieParsingError(e)
