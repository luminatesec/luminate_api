import pprint
import time

from luminateapi.dto.app_dynamic_ssh import CloudIntegrationData, Tag, Vpc
from luminateapi.dto.app_tcp import TCPTunnelSetting
from luminateapi.luminate_python import LuminateV2Client

VERIFY_SSL_CERTIFICATE = True
LUMINATE_URL = 'https://api.<tenant_name>.luminatesec.com'
API_KEY = '<api_key>'
API_SECRET = '<api_secret>'

TEST_USER_EMAIL = "block_test@<tenant_name>.luminatesec.com"

TEST_USER_EMAIL = "block_test@liorl.luminatesec.com"
if __name__ == '__main__':
    # Create a V2 Client
    luminate_client = LuminateV2Client(LUMINATE_URL,
                                       API_KEY,
                                       API_SECRET,
                                       VERIFY_SSL_CERTIFICATE)

    # Creating a Site
    site_res = luminate_client.create_site("site-test-client", "description")
    pprint.pprint(site_res)

    # HTTP Application Creation
    new_http_app_res = luminate_client.create_app_http("new_http_api", "https://127.0.0.1:8080")
    pprint.pprint(new_http_app_res)

    # Binding the Application to Site
    luminate_client.bind_app_to_site(new_http_app_res['id'], site_res['id'])

    # SSH Application Creation
    new_ssh_app_res = luminate_client.create_app_ssh("new_ssh_app",
                                                     "tcp://127.0.0.1:22",
                                                     ["some_linux_user"])
    pprint.pprint(new_ssh_app_res)

    # Dynamic RDP Application Creation
    new_rdp_app_res = luminate_client.create_app_rdp("new_rdp_app",
                                                     "tcp://127.0.0.1:3389")
    pprint.pprint(new_rdp_app_res)

    # Dynamic SSH Application Creation
    # ** Change to valid existing VPC details **
    integration_data = CloudIntegrationData(
        [
            Tag("key", "value")
        ],
        "11111111-1111-1111-1111-111111111111",
        [
            Vpc(
                "1111111111111111111111111111111111",
                "vpc-11111111",
                "ap-somewhere-1",
                "172.31.0.0/16",
                "11111111-1111-1111-1111-111111111111",
                "acmeAws"
            )
        ]
    )
    new_dynamic_ssh_app_res = luminate_client.create_app_dynamic_ssh("new_dynamic_ssh_app", integration_data)
    pprint.pprint(new_dynamic_ssh_app_res)

    # TCP Application Creation
    tcpSettings = [TCPTunnelSetting("127.0.0.1", [80, 8080])]
    new_tcp_app_res = luminate_client.create_app_tcp("new_tcp_app", tcpSettings)
    pprint.pprint(new_tcp_app_res)

    # Block all users with this email
    block_res = luminate_client.block_user_by_email(TEST_USER_EMAIL)
    pprint.pprint(block_res)

    # Unblock the same user
    unblock_res = luminate_client.unblock_user_by_email(TEST_USER_EMAIL)
    pprint.pprint(unblock_res)

    # Creating Legacy SSH Application
    # Deprecated!
    ssh_app_res = luminate_client.create_app("ssh_app",
                                             "description",
                                             "SSH",
                                             "tcp://127.0.0.1:8000",
                                             ["some_linux_user"])
    pprint.pprint(ssh_app_res)

    # Creating Legacy HTTP Application
    # Deprecated!
    http_app_res = luminate_client.create_app("http_app",
                                              "description",
                                              "HTTP",
                                              "http://127.0.0.1:8080",
                                              None)
    pprint.pprint(http_app_res)

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
