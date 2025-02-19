import os
import base64
import json
import requests

def deploy_notification(event, context):
    """Triggered from a message on a Cloud Pub/Sub topic.
    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    # print("""This Function was triggered by messageId {} published at {} to {}
    # """.format(context.event_id, context.timestamp, context.resource["name"]))

    if 'attributes' in event:
        try:
            pubsub_message = json.dumps(event['attributes'])
            message_json = json.loads(pubsub_message)
            if message_json['Action'] == "Succeed" or message_json['Action'] == "Failure":
                send_slack_chat_notification(message_json)
            else:
                print("Ignoring message")
        except Exception as e:
            print(e)
    else:
        print("Missing data payload in function trigger event")

def send_slack_chat_notification(message_json):
    slack_message = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Deploy Operation Alert for {message_json['DeliveryPipelineId']}!"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Action:*\n{message_json['Action']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*TargetId:*\n{message_json['TargetId']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*ReleaseId:*\n{message_json['ReleaseId']}"
                    }
                ]
            }
        ]
    try:
        slack_token = os.environ.get('SLACK_ACCESS_TOKEN', 'Specified environment variable is not set.')
        slack_channel = os.environ.get('SLACK_DEVOPS_CHANNEL', 'Specified environment variable is not set.')
        response = requests.post("https://slack.com/api/chat.postMessage", data={
            "token": slack_token,
            "channel": slack_channel,
            "text": f"{message_json['Action']} in {message_json['DeliveryPipelineId']} reported!",
            "blocks": json.dumps(slack_message)
        })
        print(f"Slack responded with Status Code: {response.status_code}")
        return True
    except Exception as e:
        print(e)
        raise(e)
