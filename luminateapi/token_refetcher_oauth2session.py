"""
This module implements TokenReFetcherOAuth2Session which automatically re-fetch token using the given credentials.
The specification states that Client Credentials Grant SHOULD NOT return a refresh token
(https://tools.ietf.org/html/rfc6749#section-4.4.3).
Therefore, a New token is needed when token expired.

In some cases, the API Server may require OAuth2 auth flow of its own. In this case, the API Client should perform
the OAuth request for a Luminate Session Token, and then perform the same sequence with the API Server, while
providing the Luminate Session Token in a special HTTPS Header called "lum-api-token" (while the API Server
session will use the "Authorization" Header.

for a given token:
{
    u'access_token': u'3218d2c4-294d-41cc-b6b2-92118b7916d7',
    u'scope': [u'luminate-scope'],
    u'token_type': u'Bearer',
    u'expires_in': 3600,
    u'expires_at': 1548951121.805377
}

just add
headers["lum-api-token"]='3218d2c4-294d-41cc-b6b2-92118b7916d7'

Upon receiving a request that contains both "lum-api-token" and "Authorization" headers, Luminate Secure
Access cloud assumes that the Luminate Session Token is located in the "lum-api-token" header, otherwise
authorization is performed against the content of the standard "Authorization" header.
For more information please visit https://support.luminate.io/hc/en-us/articles/360002006572

:Example:

    from oauthlib import oauth2
    from token_refetcher_oauth2session import TokenReFetcherOAuth2Session

    client = oauth2.BackendApplicationClient(client_id=CLIENT_ID)
    client.prepare_request_body()

    oauth = TokenReFetcherOAuth2Session(token_url=TOKEN_URL,
                                        client_secret=CLIENT_SECRET,
                                        client=client,
                                        verify=True)

    print oauth.get(APP_URL)
"""

import logging

import requests_oauthlib
from oauthlib.oauth2 import rfc6749


class TokenReFetcherOAuth2Session(requests_oauthlib.OAuth2Session):
    """
        Makes sure that when request return with TokenExpiredError, it will re-fetch a
        new token with the same credentials and retry the request.
        Extends requests_oauthlib.OAuth2Session.

        :param token_url: Token endpoint URL, must use HTTPS.
        :param client_secret -- client_secret as provided by the OAuth Provider
        :param verify: Verify SSL certificate.
    """

    def __init__(self, token_url, client_secret, verify, **kwargs):
        self.token_url = token_url
        self.client_secret = client_secret
        self.verify = verify
        self._logger = logging.getLogger(__name__)
        self._token = None

        super(TokenReFetcherOAuth2Session, self).__init__(**kwargs)

        self.fetch_token()

    def request(self, method, url, data=None, headers=None, **kwargs):
        try:
            return self.__make_request(method, url, headers=headers, data=data, **kwargs)
        except rfc6749.errors.TokenExpiredError:
            self.fetch_token()

            return self.__make_request(method, url, headers=headers, data=data, **kwargs)

    def __make_request(self, method, url, data=None, headers=None, **kwargs):
        return super(TokenReFetcherOAuth2Session, self).request(method, url, headers=headers, data=data, **kwargs)

    def fetch_token(self):
        self._logger.debug("Refreshing Token")
        return super(TokenReFetcherOAuth2Session, self).fetch_token(token_url=self.token_url,
                                                                    client_id=self.client_id,
                                                                    client_secret=self.client_secret,
                                                                    verify=self.verify)
