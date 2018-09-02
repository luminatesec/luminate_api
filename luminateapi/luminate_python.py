#!/usr/bin/python

import logging
from oauthlib.oauth2 import BackendApplicationClient
from token_refetcher_oauth2session import TokenReFetcherOAuth2Session


class HTTPError(IOError):
    def __init__(self, *args, **kwargs):
        """Initialize HTTPError with `response` objects."""
        response = kwargs.pop('response', None)
        self.response = response
        super(IOError, self).__init__(*args, **kwargs)

    def __str__(self):
        return '{} with status code: {}'.format(self.message, self.response.status_code)


class Luminate(object):
    """User interface to Luminate.
    Clients interact with Luminate by constructing an instance of this object and calling its methods.
    """

    def __init__(self, server, rest_api_version, client_id, client_secret, verify_ssl=True):
        """Construct a Luminate client instance.
        :param server -- luminate api for authenticating, should be like with https://api.<tenant>.luminatesec.com.
        :param rest_api_version -- the version of the REST resources under rest_path to use. Defaults to ``2``.
        :param client_id -- client_id as provided by the OAuth Provider (Luminate Security)
        :param client_secret -- client_secret as provided by the OAuth Provider (Luminate Security)
        """
        self._options = {'server': server, 'rest_api_version': rest_api_version}

        self._create_oauth_session(client_id, client_secret, verify_ssl)
        self._logger = logging.getLogger(__name__)

    def _create_oauth_session(self, client_id, client_secret, verify_ssl=True):

        token_url = '{}/v1/oauth/token'.format(self._options['server'])

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

        url_template = '{}/v{}/identities/settings/blocked-users'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for blocking users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 201:
            raise HTTPError("failed to block user", response=response)

    def unblock_user(self, user_id, identity_provider_id):
        """
        Unblock the given user
        :param user_id: the user_id (not email) identifies the user in the provided identity_provider_id
        :param identity_provider_id: id of the identity_provider installed
        :return: None
        :exception: HTTPError in case of unexpected status code
        """

        url_template = '{}/v{}/identities/settings/blocked-users'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.delete(url, json=payload)
        self._logger.debug("Request to Luminate for unblocking users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 204:
            raise HTTPError("failed to unblock user", response=response)

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

        url_template = '{}/v{}/logs/access'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'size': size,
            'query': query,
            'search_after': search_after,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for access logs: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 200:
            raise HTTPError("failed to get access logs", response=response)

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

        url_template = '{}/v{}/logs/ssh'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'size': size,
            'query': query,
            'search_after': search_after,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for ssh access logs: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 200:
            raise HTTPError("failed to get ssh access logs", response=response)

        return response.json()

    def get_user(self, user_email):
        """
        Gets all users with this email from all installed identity providers
        :param user_email: the user email
        :return: json with the results
        :exception: HTTPError in case of unexpected status code
        """

        url_template = '{}/v{}/identities/users?email={}'
        url = url_template.format(self._options['server'], self._options['rest_api_version'], user_email)

        response = self._session.get(url)
        self._logger.debug("Request to Luminate for getting users: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 200:
            raise HTTPError("failed to get user by email", response=response)

        return response.json()

    def destroy_user_session(self, user_id, identity_provider_id):
        """
        Destroy all sessions of the user_id from the  identity_provider_id
        :param user_id: unique id for a single user
        :param identity_provider_id: the identity provider id the user belongs to
        :return: None
        :exception: HTTPError in case of unexpected status code
        """

        url_template = '{}/v{}/sessions/destroy'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'identity_provider_id': identity_provider_id,
            'user_id': user_id,
        }

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for destroy users sessions: returned response: %s, status code:%s"
                           % (response.content, response.status_code))

        if response.status_code != 204:
            raise HTTPError("failed to destroy user sessions", response=response)

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
            except HTTPError, e:
                if user.provider_name not in res["failure"]:
                    res["failure"][user.provider_name] = []
                res["failure"][user.provider_name].append({user.id: str(e)})
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

    def create_app(self, app_name, description, app_type, internal_address, site_name, ssh_users):
        """Create a new Application at a specific Site.
        :param app_name: Application Name
        :param description: A string which describes the application
        :param app_type: Application type - Valid values are HTTP, SSH.
        :param internal_address: Application internal IP
        :param site_name: The name of the site on which this application resides.
        :param ssh_users: A list of user names that are available for SSH log-in on the remote ssh machine.

        """
        connection_settings = {'internal_address': internal_address}

        url_template = '{}/v{}/applications'
        url = url_template.format(self._options['server'], self._options['rest_api_version'])

        payload = {
            'name': app_name,
            'description': description,
            'type': app_type,
            'connection_settings': connection_settings,
            'site_name': site_name,
        }

        if app_type == 'SSH':
            if ssh_users:
                payload['ssh_users'] = ssh_users
            else:
                raise ValueError('A request for creating an SSH application must include SSH users')

        response = self._session.post(url, json=payload)
        self._logger.debug("Request to Luminate for creating an application :%s returned response: %s, status code:%s"
                           % (app_name, response.content, response.status_code))

        if response.status_code != 201:
            response.raise_for_status()
            return None

        data = response.json()

        return data['id']

    def update_app(self, app_id, app_name, description, app_type, internal_address, site_name, ssh_users):
        """Updates an existing application.
        :param app_id: Application ID
        :param app_name: Application Name
        :param description: A string which describes the application
        :param app_type: Application type - Valid values are HTTP, SSH.
        :param internal_address: Application internal IP
        :param site_name: The name of the site on which this application resides.
        :param ssh_users: A list of user names that are available for SSH log-in on the remote ssh machine.

         """

        connection_settings = {'internal_address': internal_address}

        url_template = '{}/v{}/applications/{}'

        url = url_template.format(self._options['server'], self._options['rest_api_version'], app_id)
        payload = {
            'name': app_name,
            'description': description,
            'type': app_type,
            'connection_settings': connection_settings,
            'site_name': site_name,
        }

        if app_type == 'SSH':
            if ssh_users:
                payload['ssh_users'] = ssh_users
            else:
                raise ValueError(
                    'Request to Luminate for updating an application %s failed - missing SSH users' % app_name)

        response = self._session.put(url, json=payload)
        self._logger.debug("Request to Luminate for updating an application :%s returned response: %s, status code:%s"
                           % (app_name, response.content, response.status_code))

        if response.status_code != 200:
            response.raise_for_status()
            return -1

        return 0

    def assign_user_to_app(self, app_id, email, idp, ssh_users):
        """
        Assign a user to an application.
        :param app_id: Application ID
        :param email: The e-mail address of the user to whom you would like to grant access to the application.
        :param idp: Identity Provider of the user.
        :param ssh_users: A list of user names with which the user will be able to log-in to the ssh machine.

        """

        url_template = '{}/v{}/applications/{}/assign-user'

        url = url_template.format(self._options['server'], self._options['rest_api_version'], app_id)
        payload = {
            'email': email,
            'idp_name': idp
        }

        if ssh_users:
            payload['ssh_users'] = ssh_users
            self._logger.debug("SSH users: %s were defined for user: %s" % (ssh_users, email))

        response = self._session.post(url, json=payload)

        self._logger.debug("Request to Luminate for assigning a user :%s to application %s returned response:\n %s,\
                            status code:%s" % (email, app_id, response.content, response.status_code))

        if response.status_code != 200:
            response.raise_for_status()
            return -1

        return 0

    def assign_group_to_app(self, app, name, idp, ssh_users):
        """
        Assign a group to an application.
        :param app: Application ID
        :param name: The name of the group to which you would like to grant access to the application.
        :param idp: Identity Provider of the group.
        :param ssh_users: A list of user names with which the group members will be able to log-in to the ssh machine.

        """

        url_template = '{}/v{}/applications/{}/assign-group'

        url = url_template.format(self._options['server'], self._options['rest_api_version'], app)
        payload = {
            'name': name,
            'idp_name': idp
        }

        if ssh_users:
            payload['ssh_users'] = ssh_users
            self._logger.debug("SSH users: %s were defined for group: %s" % (ssh_users, name))

        response = self._session.post(url, json=payload)

        self._logger.debug("Request to Luminate for assigning a group :%s to application %s returned response:\n %s,\
                            status code:%s" % (name, app, response.content, response.status_code))

        if response.status_code != 200:
            response.raise_for_status()
        return 0

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
