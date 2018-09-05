#!/usr/bin/python

import logging

from oauthlib.oauth2 import BackendApplicationClient

from .token_refetcher_oauth2session import TokenReFetcherOAuth2Session


class LuminateV2Client(object):
    """User interface to Luminate.
    Clients interact with Luminate by constructing an instance of this object and calling its methods.
    """

    def __init__(self, server, client_id, client_secret, verify_ssl=True):
        """Construct a Luminate client instance.
        :param server -- luminate api for authenticating, should be like with https://api.<tenant>.luminatesec.com.
        :param client_id -- client_id as provided by the OAuth Provider (Luminate Security)
        :param client_secret -- client_secret as provided by the OAuth Provider (Luminate Security)
        """
        self._server = server
        self._create_oauth_session(client_id, client_secret, verify_ssl)
        self._logger = logging.getLogger(__name__)
        self._api_version = 'v2'

    def _create_oauth_session(self, client_id, client_secret, verify_ssl=True):

        token_url = '{}/v1/oauth/token'.format(self._server)

        client = BackendApplicationClient(client_id=client_id)
        client.prepare_request_body()
        oauth = TokenReFetcherOAuth2Session(token_url=token_url,
                                            client_secret=client_secret,
                                            client=client,
                                            verify=verify_ssl)

        self._session = oauth

    def block_user(self, user_id, identity_provider_id):
        """
        Blocks the given user
        :param user_id: the user_id (not email) identifies the user in the provided identity_provider_id
        :param identity_provider_id: id of the identity_provider installed
        :return: None
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/identities/settings/blocked-users'.format(self._server, self._api_version)

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for blocking users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)

    def unblock_user(self, user_id, identity_provider_id):
        """
        Unblock the given user
        :param user_id: the user_id (not email) identifies the user in the provided identity_provider_id
        :param identity_provider_id: id of the identity_provider installed
        :return: None
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/identities/settings/blocked-users'.format(self._server, self._api_version)

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.delete(url, json=payload)
        self._logger.debug("Request to Luminate for unblocking users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)

    def get_access_logs(self, size, query, search_after):
        """
        Gets HTTP Access logs from Luminate
        For more info https://luminatepublicapi.docs.apiary.io
        :param size: The maximum number of results to return. This is limited to 1000, and defaults to 1000
        :param query: json describe the query
        :param search_after: Using search_after you may page through results, You will need to provide the search_after
        values of the last log line in the previous result.
        :return: json with the results
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/logs/access'.format(self._server, self._api_version)

        payload = {
            'size': size,
            'query': query,
            'search_after': search_after,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for access logs: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def get_ssh_access_logs(self, size, query, search_after):
        """
        Gets SSH Access logs from Luminate
        For more info https://luminatepublicapi.docs.apiary.io
        :param size: The maximum number of results to return. This is limited to 1000, and defaults to 1000
        :param query: json describe the query
        :param search_after: Using search_after you may page through results, You will need to provide the search_after
        values of the last log line in the previous result.
        :return: json with the results
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/logs/ssh'.format(self._server, self._api_version)

        payload = {
            'size': size,
            'query': query,
            'search_after': search_after,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for ssh access logs: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def get_alerts(self, size, query, search_after):
        """
        Gets Alerts from Luminate
        For more info https://luminatepublicapi.docs.apiary.io
        :param size: The maximum number of results to return. This is limited to 1000, and defaults to 1000
        :param query: json describe the query
        :param search_after: Using search_after you may page through results, You will need to provide the search_after
        values of the last log line in the previous result.
        :return: json with the results
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/logs/alerts'.format(self._server, self._api_version)

        payload = {
            'size': size,
            'query': query,
            'search_after': search_after,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for alerts: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def get_user(self, user_email):
        """
        Gets all users with this email from all installed identity providers
        :param user_email: the user email
        :return: json with the results
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/identities/users?email={}'.format(self._server, self._api_version, user_email)

        response = self._session.get(url)
        self._logger.debug("Request to Luminate for getting users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def destroy_user_session(self, user_id, identity_provider_id):
        """
        Destroy all sessions of the user_id from the  identity_provider_id
        :param user_id: unique id for a single user
        :param identity_provider_id: the identity provider id the user belongs to
        :return: None
        :exception: HTTPError in case of unexpected status code
        """

        url = '{}/{}/sessions/destroy'.format(self._server, self._api_version)

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for destroy users sessions: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        raise_for_status(response)

    def __batch_execute(self, f, user_email):
        res = {"success": {}, "failure": {}}

        results = self.get_user(user_email)
        users = self.__filter_safe_user_id_identity_provider(results)

        for user in users:
            try:
                f(user.id, user.provider_id)
                if user.provider_name not in res["success"]:
                    res["success"][user.provider_name] = []
                res["success"][user.provider_name].append({user.id: "DONE"})
            except HTTPError as e:
                if user.provider_name not in res["failure"]:
                    res["failure"][user.provider_name] = []
                res["failure"][user.provider_name].append({user.id: e.to_json()})
        return res

    def block_user_by_email(self, user_email):
        """
        Blocks all users with this email from all identity providers
        :param user_email: the user email to block
        :return: json with success and failure fields
        """

        return self.__batch_execute(self.block_user, user_email)

    def unblock_user_by_email(self, user_email):
        """
        Un Blocks all users with this email from all identity providers
        :param user_email: the user email to unblock
        :return:  json with success and failure fields
        """

        return self.__batch_execute(self.unblock_user, user_email)

    def destroy_user_sessions_by_email(self, user_email):
        """
        Disconnect all sessions of that user
        :param user_email: the user email
        :return: json with success and failure fields
        """

        return self.__batch_execute(self.destroy_user_session, user_email)

    def create_app(self, app_name, description, app_type, internal_address, ssh_users):
        """Create a new Application at a specific Site.
        :param app_name: Application Name
        :param description: A string which describes the application
        :param app_type: Application type - Valid values are HTTP, SSH.
        :param internal_address: Application internal IP
        :param ssh_users: A list of user names that are available for SSH log-in on the remote ssh machine.

        """

        url = '{}/{}/applications'.format(self._server, self._api_version)

        payload = {
            'connectionSettings': {
                "internalAddress": internal_address
            },
            'description': description,
            'type': app_type,
            'name': app_name,
        }

        if app_type == 'SSH':
            if ssh_users:
                payload['sshSettings'] = {"userAccounts": [{"name": x} for x in ssh_users]}
            else:
                raise ValueError('A request for creating an SSH application must include SSH users')

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for creating an application :%s returned response: %s, status code:%s"
                           % (app_name, response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def create_site(self, site_name, description):
        """Create a new Application at a specific Site.
        :param description: A string which describes the application
        :param site_name: The name of the site on which this application resides.

        """

        url = '{}/{}/sites/'.format(self._server, self._api_version)
        payload = {
            'name': site_name,
            'description': description,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for creating an site :%s returned response: %s, status code:%s"
                           % (site_name, response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    def bind_app_to_site(self, application_id, site_id):
        """Assign your Application to an existing Site.
        :param application_id: the application_id to bind to the site
        :param site_id: the id of the site to bind the application to
        """

        url = '{}/{}/applications/{}/site-binding/{}'.format(self._server, self._api_version, application_id, site_id)
        headers = {'Content-type': 'application/json'}

        response = self._session.put(url, headers=headers)
        self._logger.debug(
            "Request to Luminate for binding application to site:%s returned response: %s, status code:%s"
            % (site_id, response.content, response.status_code))

        raise_for_status(response)

    def assign_entity_to_app(self, app_id, identifier_in_provider, identity_provider_id,
                             identity_provider_type, entity_type):
        """
        Assign a user to an application.
        :param app_id: Application ID
        :param identifier_in_provider: The identifier of this entity in the identity provider owning this directory entity.
        :param identity_provider_id: The identity provider owning this directory entity.
        :param identity_provider_type: The identity provider owning this directory entity (Local/ActiveDirectory/Okta).
        :param entity_type: type as sting can be User/Group/OU

        """

        url_template = '{}/{}/applications/{}/directory-entity-bindings/'

        url = url_template.format(self._server, self._api_version, app_id)
        payload = {
            'directoryEntity': {
                'identifierInProvider': identifier_in_provider,
                'identityProviderId': identity_provider_id,
                'identityProviderType': identity_provider_type,
                'type': entity_type
            }
        }

        response = self._session.put(url, json=payload)

        self._logger.debug("Request to Luminate for assigning a user :%s to application %s returned response:\n %s,\
                            status code:%s" % (identifier_in_provider, app_id, response.content, response.status_code))

        raise_for_status(response)
        return response.json()

    @staticmethod
    def __filter_safe_user_id_identity_provider(results):
        r = []
        for res in results:
            if "id" in res and res['id'] is not None:
                if "users" in res and res['users'] is not None:
                    for user in res["users"]:
                        if "id" in user and user["id"] is not None:
                            r.append(UserInst(user['email'], user['id'], res['id'], res['name']))
        return r


class UserInst(object):
    def __init__(self, user_email, user_id, provider_id, provider_name):
        self.email = user_email
        self.id = user_id
        self.provider_id = provider_id
        self.provider_name = provider_name


class HTTPError(Exception):
    def __init__(self, message, response):
        self.message = message
        self.response = response

    def __str__(self):
        return '{} with content: {}'.format(self.message, self.response.text)

    def to_json(self):
        return {
            "content": self.response.content,
            "status_code": self.response.status_code,
            "message": self.message
        }


def raise_for_status(requests_response):
    """Raises stored :class:`HTTPError`, if one occurred."""

    http_error_msg = ''
    if isinstance(requests_response.reason, bytes):
        # We attempt to decode utf-8 first because some servers
        # choose to localize their reason strings. If the string
        # isn't utf-8, we fall back to iso-8859-1 for all other
        # encodings. (See PR #3538)
        try:
            reason = requests_response.reason.decode('utf-8')
        except UnicodeDecodeError:
            reason = requests_response.reason.decode('iso-8859-1')
    else:
        reason = requests_response.reason

    if 400 <= requests_response.status_code < 500:
        http_error_msg = u'%s Client Error: %s for url: %s' % (
            requests_response.status_code, reason, requests_response.url)

    elif 500 <= requests_response.status_code < 600:
        http_error_msg = u'%s Server Error: %s for url: %s' % (
            requests_response.status_code, reason, requests_response.url)

    if http_error_msg:
        raise HTTPError(http_error_msg, response=requests_response)
