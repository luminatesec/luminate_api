import logging
from oauthlib.oauth2 import BackendApplicationClient
from luminateapi.token_refetcher_oauth2session import TokenReFetcherOAuth2Session

VERIFY_SSL_CERTIFICATE = True
LUMINATE_URL = 'https://api.<tenant_name>.luminatesec.com'
API_KEY = '<api_key>'
API_SECRET = '<api_secret>'


def create_lumiante_session(tenant_path, client_id, client_secret, verify_ssl_certificate=True):
    token_url = '{}/v1/oauth/token'.format(tenant_path)

    client = BackendApplicationClient(client_id=client_id)
    client.prepare_request_body()
    oauth = TokenReFetcherOAuth2Session(token_url=token_url,
                                        client_secret=client_secret,
                                        client=client,
                                        verify=verify_ssl_certificate)

    return oauth


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    session = create_lumiante_session(LUMINATE_URL, API_KEY, API_SECRET, VERIFY_SSL_CERTIFICATE)

    protected_url = "https://<app_name>.<tenant_name>.luminatesec.com"

    res = session.get(protected_url)
    res.json()
