import pprint
import time

from luminateapi.luminate_python import LuminateV2Client

LUMINATE_URL = 'https://api.<tenant_name>.luminatesec.com'
API_KEY = '<api_key>'
API_SECRET = '<api_secret>'
VERIFY_CERTIFICATE = True

TEST_USER_EMAIL = "block_test@dodger.luminatesite.com"

if __name__ == '__main__':
    # Create a V2 Client
    luminate_client = LuminateV2Client(LUMINATE_URL,
                                       API_KEY,
                                       API_SECRET,
                                       VERIFY_CERTIFICATE)

    # Block all users with this email
    block_res = luminate_client.block_user_by_email(TEST_USER_EMAIL)
    pprint.pprint(block_res)

    # Unblock the same user
    unblock_res = luminate_client.unblock_user_by_email(TEST_USER_EMAIL)
    pprint.pprint(unblock_res)

    # Creating SSH Application
    ssh_app_res = luminate_client.create_app("client-ssh-test91",
                                             "description",
                                             "SSH",
                                             "tcp://127.0.0.1:8000",
                                             ["some_linux_user"])
    pprint.pprint(ssh_app_res)

    # Creating HTTP Application
    http_app_res = luminate_client.create_app("client-http-app",
                                              "description",
                                              "HTTP",
                                              "http://127.0.0.1:8080",
                                              None)
    pprint.pprint(http_app_res)

    # Creating a Site
    site_res = luminate_client.create_site("site-test-client", "description")
    pprint.pprint(site_res)

    # Binding the Application to Site
    luminate_client.bind_app_to_site(http_app_res['id'], site_res['id'])

    # Get user information
    user_info_res = luminate_client.get_user(TEST_USER_EMAIL)
    pprint.pprint(user_info_res)

    # Finding local IDP
    local_idp = None
    for idp in user_info_res:
        if idp['name'] == 'local':
            local_idp = idp
    assert (local_idp is not None)

    local_user = local_idp['users'][0]

    # Assigning the user to the created application
    assignment_res = luminate_client.assign_entity_to_app(http_app_res['id'],
                                                          local_user['id'],
                                                          local_user['identity_provider_id'],
                                                          local_user['repository_type'],
                                                          "User")
    print(assignment_res)

    # Destroy User Session
    destroy_res = luminate_client.destroy_user_sessions_by_email(TEST_USER_EMAIL)
    pprint.pprint(destroy_res)

    # Getting HTTP and SSH logs
    query = {
        "free_text": "",
        "from_date": int((time.time() - 1000) * 1000),
        "to_date": int(time.time() * 1000),
    }

    http_logs_res = luminate_client.get_access_logs(2, query, None)
    pprint.pprint(http_logs_res)

    ssh_logs_res = luminate_client.get_ssh_access_logs(2, query, None)
    pprint.pprint(ssh_logs_res)

    # Get Alerts
    alert_logs_res = luminate_client.get_alerts(2, query, None)
    pprint.pprint(alert_logs_res)
