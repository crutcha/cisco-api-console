import datetime
import json
import logging
import requests
from cachetools import TTLCache
from api_exception import *
from settings import client_id, client_secret

logger = logging.getLogger(__name__)


class BaseCiscoApiConsole:
    """
    Basic Cisco API implementation
    This class implements the OAuth2 authentication process, get a token from the central authentication directory and
    caches the resulting access token.
    """
    AUTH_TOKEN_CACHE_KEY = "cisco_api_auth_token"
    AUTHENTICATION_URL = "https://cloudsso.cisco.com/as/token.oauth2"

    current_access_token = None
    http_auth_header = None
    token_expire_datetime = datetime.datetime.now()

    cache = TTLCache(maxsize=150, ttl=3600)

    # just for testing, indicates, that the class has claimed new token
    __new_token_created__ = False

    def __repr__(self):
        return {
            "cliend_id": self.client_id,
            "http_auth_header": self.http_auth_header,
            "current_access_token": self.current_access_token        }

    def load_client_credentials(self):
        logger.debug("load client credentials from configuration")

        # load client credentials
        self.client_id = client_id
        self.client_secret = client_secret 

    def __save_cached_temp_token__(self):
        logger.debug("save token to cache")

        temp_auth_token = dict()
        temp_auth_token['http_auth_header'] = self.http_auth_header        
        temp_auth_token['expire_datetime'] = self.token_expire_datetime.strftime("%Y-%m-%d %H:%M:%S.%f")

        self.cache[self.AUTH_TOKEN_CACHE_KEY] = json.dumps(temp_auth_token)

        logger.info("temporary token saved")

    def __load_cached_temp_token__(self):
        logger.debug("load cached temp token")

        try:
            cached_auth_token = self.cache.get(self.AUTH_TOKEN_CACHE_KEY)
            if not cached_auth_token:
                return False
            temp_auth_token = json.loads(cached_auth_token)

            self.http_auth_header = temp_auth_token['http_auth_header']
            self.token_expire_datetime = datetime.datetime.strptime(
                temp_auth_token['expire_datetime'],
                "%Y-%m-%d %H:%M:%S.%f"
            )
            return True

        except:
            logger.info("cannot load cached token: register new token")
            return False

    def get_client_credentials(self):
        if self.client_id is None:
            self.load_client_credentials()

        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret        }

    def create_temporary_access_token(self, force_new_token=False):
        logger.debug("create new temporary token")
        if self.client_id is None:
            raise CredentialsNotFoundException("Client credentials not defined/found")

        authz_header = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }

        # check if previous token expired
        if self.__is_cached_token_valid__():
            logger.info("cached token valid, continue with it")

        else:
            logger.info("cached token invalid or not existing (force:%s)" % force_new_token)
            try:
                result = requests.post(self.AUTHENTICATION_URL, params=authz_header)

            except Exception as ex:
                logger.error("cannot contact authentication server at %s" % self.AUTHENTICATION_URL, exc_info=True)
                raise ConnectionFailedException("cannot contact authentication server") from ex

            if result.status_code == 401:
                # unauthorized
                logger.error("cannot claim access token, Invalid client or client credentials")
                raise InvalidClientCredentialsException("Invalid client or client credentials")

            if result.text.find("Not Authorized") != -1:
                logger.error("cannot claim access token, authorization failed")
                raise AuthorizationFailedException("Not Authorized")

            else:
                self.drop_cached_token()
                self.current_access_token = json.loads(result.text)
                self.__new_token_created__ = True

            # set expire date
            expire_offset = datetime.timedelta(seconds=self.current_access_token['expires_in'])
            self.token_expire_datetime = datetime.datetime.now() + expire_offset

        self.http_auth_header = {
            # we will just work with JSON results
            "Accept": "application/json",
            "Authorization": "%s %s" % (self.current_access_token['token_type'],
                                        self.current_access_token['access_token']),
        }

        # dump token to temp file
        self.__save_cached_temp_token__()

    def drop_cached_token(self):
        try:
            self.cache.pop(self.AUTH_TOKEN_CACHE_KEY)

        except Exception as ex:
            logger.error("cannot delete cache value: %s" % str(ex), exc_info=True)
            pass

        self.current_access_token = None
        self.http_auth_header = None

    def __is_cached_token_valid__(self):
        if self.token_expire_datetime is not None:
            logger.debug("check cached token state: %s <= %s" % (datetime.datetime.now(),
                                                                 self.token_expire_datetime))
            return datetime.datetime.now() <= self.token_expire_datetime
        return False

    def is_ready_for_use(self):
        """
        verify the state of the class
        :return:
        """
        if self.client_id is None:
            raise CredentialsNotFoundException("credentials not loaded")

        if self.http_auth_header is None:
            # check that a valid token exists, renew if required
            if not self.__load_cached_temp_token__():
                self.create_temporary_access_token(force_new_token=True)
            else:
                if not self.__is_cached_token_valid__():
                    logger.info("access token expired, claim new one")
                    self.create_temporary_access_token(force_new_token=True)

        elif not self.__is_cached_token_valid__():
            logger.info("access token expired, claim new one")
            self.create_temporary_access_token(force_new_token=True)

        return True


class CiscoHelloApi(BaseCiscoApiConsole):
    """
    Implementation of the Cisco Hello API endpoint (only for testing)
    """
    HELLO_API_URL = "https://api.cisco.com/hello"

    def hello_api_call(self):
        logger.debug("call to Hello API endpoint")
        if self.is_ready_for_use():
            try:
                print(self.http_auth_header)
                result = requests.get(self.HELLO_API_URL, headers=self.http_auth_header)

            except Exception as ex:
                logger.error("cannot contact API endpoint at %s" % self.HELLO_API_URL, exc_info=True)
                raise ConnectionFailedException("cannot contact API endpoint at %s" % self.HELLO_API_URL) from ex

            if result.text.find("Not Authorized") != -1:
                logger.debug("call not authorized: %s" % result.text)
                raise AuthorizationFailedException("Not Authorized")

            return result.json()
        raise CiscoApiCallFailed("Client not ready (credentials or token missing)")

class CiscoSn2infoApi(BaseCiscoApiConsole):

    '''
    Implementation of Cisco Serial number to information API. This will get device coverage for managed devices.
    '''
    SN2INFO_API_URL = 'https://api.cisco.com/sn2info/v2/coverage/summary/serial_numbers/{0}'
    SN2INFO_COVERAGE_END_URL = 'https://api.cisco.com/sn2info/v2/coverage/owner_status/serial_numbers/{0}'

    def sn2info_api_call(self, serial_num):
        logger.debug('call to sn2info API endpoint')

        if self.is_ready_for_use():
            try:
                result = requests.get(self.SN2INFO_API_URL.format(serial_num), headers=self.http_auth_header, timeout=15)
            except Exception as ex:
                logger.error('cannot contact API endpoint at {}'.format(self.SN2INFO_API_URL))
                raise ConnectionFailedException('cannot contact API endpoint at {}'.format(self.SN2INFO_API_URL))

            return result.json()

        raise CiscoApiCallFailed('Client not ready (credentails or token missing)')

    def sn2info_api_coverage_end_api_call(self, serial_num):
        logger.debug('call to sn2info API endpoint for coverage end info')

        if self.is_ready_for_use():
            try:
                result = requests.get(self.SN2INFO_COVERAGE_END_URL.format(serial_num), headers=self.http_auth_header, timeout=15)
            except Exception as ex:
                logger.error('cannot contact API endpoint at {}'.format(self.SN2INFO_COVERAGE_END_URL))
                raise ConnectionFailedException('cannot contact API endpoint at {}'.format(self.SN2INFO_COVERAGE_END_URL))

            return result.json()

        raise CiscoApiCallFailed('Client not ready (credentails or token missing)')


class CiscoBugApi(BaseCiscoApiConsole):

    '''
    Implementation of Cisco Bugv2 API.
     '''
    BUG_API_URL = 'https://api.cisco.com/bug/v2.0/bugs/products/product_id/{0}/software_releases/{1}'

    def bug_api_call(self, base_pid, sw_ver):
        logger.debug('call to bug API endpoint')

        if self.is_ready_for_use():
            try:
                result = requests.get(self.BUG_API_URL.format(base_pid, sw_ver), headers=self.http_auth_header, timeout=15)
            except Exception as ex:
                logger.error('cannot contact API endpoint at {}'.format(self.BUG_API_URL))
                raise ConnectionFailedException('cannot contact API endpoint at {}'.format(self.BUG_API_URL))

            return result.json()

        raise CiscoApiCallFailed('Client not ready (credentails or token missing)')


class CiscoSWSuggestionApi(BaseCiscoApiConsole):
    '''
    Using Cisco Software Suggestions API, use basepid to
    get suggested software for given device.
    '''

    SW_SUGGEST_API_URL = 'https://api.cisco.com/software/suggestion/v1.0/suggestions/software/{0}'

    def sw_suggestion_api_call(self, base_pid):
        logger.debug('call to software suggestion API endpoint')

        if self.is_ready_for_use():
            try:
                result = requests.get(self.SW_SUGGEST_API_URL.format(base_pid), headers=self.http_auth_header, timeout=15)
            except Exception as ex:
                logger.error('cannot contact API endpoint at {}'.format(self.SW_SUGGEST_API_URL))
                raise ConnectionFailedException('cannot contact API endpoint at {}'.format(self.SW_SUGGEST_API_URL))

            return result.json()

        raise CiscoApiCallFailed('Client not ready (credentails or token missing)')

class CiscoEoXApiBySerial(BaseCiscoApiConsole):
    '''
    Grab EoX record based on serial number.
    '''

    EOX_API_URL = 'https://api.cisco.com/supporttools/eox/rest/5/EOXBySerialNumber/1/{}?responseencoding=json'

    def eox_api_call(self, serial_num):
        logger.debug('call to EoX API endpoint')

        if self.is_ready_for_use():
            try:
                result = requests.get(self.EOX_API_URL.format(serial_num), headers=self.http_auth_header, timeout=15)
            except Exception as ex:
                logger.error('cannot contact API endpoint at {}'.format(self.EOX_API_URL))
                raise ConnectionFailedException('cannot contact API endpoint at {}'.format(self.EOX_API_URL))

            return result.json()

        raise CiscoApiCallFailed('Client not ready (credentials or token missing)')


