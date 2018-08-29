"""
This module implements TokenReFetcherOAuth2Session which automatically re-fetch token using the given credentials.
The specification states that Client Credentials Grant SHOULD NOT return a refresh token
(https://tools.ietf.org/html/rfc6749#section-4.4.3).
Therefore, a New token is needed when token expired.

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

        super(TokenReFetcherOAuth2Session, self).__init__(**kwargs)

        self.fetch_token()

    def request(self, method, url, data=None, headers=None, withhold_token=False,
                client_id=None, client_secret=None, **kwargs):
        try:
            return super(TokenReFetcherOAuth2Session, self).request(method, url,
                                                                    headers=headers, data=data, **kwargs)
        except rfc6749.errors.TokenExpiredError:
            self._logger.debug("TokenExpiredError, Refreshing!")
            self.fetch_token()

            return super(TokenReFetcherOAuth2Session, self).request(method, url,
                                                                    headers=headers, data=data, **kwargs)

    def fetch_token(self):

        return super(TokenReFetcherOAuth2Session, self).fetch_token(token_url=self.token_url,
                                                                    client_id=self.client_id,
                                                                    client_secret=self.client_secret,
                                                                    verify=self.verify)
