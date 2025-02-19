import time
import json
import requests
from google.cloud import securitycenter
from pytz import timezone
from datetime import datetime

def mute_finding(request):
    # processing the mute_finding request
    event = json.loads(request.get_data().decode('UTF-8'))
    response_timestamp = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')
    project_name = event['value'].split("project_name=")[1].split("+")[0]
    resource_name = event['value'].split("resource_name=")[1].split("+")[0]
    resource_type = event['value'].split("resource_type=")[1].split("+")[0].split(".")[-1]
    finding_path = event['value'].split("finding_path=")[1].split("+")[0]
    finding_id = finding_path.split("findings/")[1]
    
    result = set_mute_finding(finding_path)
    if result:
        response_subject = "SCC finding muted successfully!"
    else:
        response_subject = "SCC finding muted action failed!"

    slack_message = {
        "text": f"{response_subject}\n",
        "blocks": [ 
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Mute Action Taken"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{response_subject}\n"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Requestor:*\n{event['caller_name']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*When:*\n{response_timestamp} IST"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Finding ID:*\n{finding_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Resource:*\nProject/{project_name}/{resource_type}/{resource_name}"
                    }
                ]
            }
        ]
    }
    post_slack_response(event['response_url'],slack_message)
    return {
        'statusCode': 200,
        'body': json.dumps("Completed!")
    }

def set_mute_finding(finding_path):
    try:
        print(f"Muting finding: {finding_path}...")
        client = securitycenter.SecurityCenterClient()

        request = securitycenter.SetMuteRequest()
        request.name = finding_path
        request.mute = securitycenter.Finding.Mute.MUTED

        finding = client.set_mute(request)
        print(f"Mute value for the finding: {finding.mute.name}")
        if finding.mute.name == "MUTED":
            return True
        else:
            return False
    except Exception as e:
        print(e)
        raise(e)

def post_slack_response(response_url,slack_message):
    response = requests.post(response_url, data=json.dumps(slack_message), headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        print("Slack response sent successfully.")
        return True
    else:
        print("Slack response failed.")
        return False