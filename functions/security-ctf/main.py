import os
import time
import json
import hmac
import hashlib
import urllib.parse
import requests
import google.auth.transport.requests
import google.oauth2.id_token
from requests.structures import CaseInsensitiveDict

def security_ctf(request):
    # extracting payload information from POST
    timestamp = request.headers['X-Slack-Request-Timestamp']
    payload = request.get_data().decode('utf-8')
    slack_signature = request.headers['X-Slack-Signature']
    slack_signing_secret = os.environ.get('SLACK_SIGNING_SECRET', 'Specified environment variable is not set.')
    slack_ctf_admin_channel = os.environ.get('SLACK_CTF_ADMIN_CHANNEL', 'Specified environment variable is not set.')
    deployment_project = os.environ.get('DEPLOYMENT_PROJECT', 'Specified environment variable is not set.')
    deployment_region = os.environ.get('DEPLOYMENT_REGION', 'Specified environment variable is not set.')
    slack_admin = os.environ.get('SLACK_ADMIN', 'Specified environment variable is not set.')

    if verify_request(timestamp,payload,slack_signature,slack_signing_secret):
        if payload.startswith("token="):
            # parse the slash command for access request
            url = urllib.parse.unquote(payload.split("response_url=")[1].split("&")[0])
            requestor_name = payload.split("user_name=")[1].split("&")[0]
            requestor_id = payload.split("user_id=")[1].split("&")[0]
            channel_id = payload.split("channel_id=")[1].split("&")[0]
            request_text = urllib.parse.unquote(payload.split("text=")[1].split("&")[0])
            print(f"New CTF Request: {requestor_id}, {requestor_name}, {request_text}")
            
            input_text = request_text.split("+")
            if input_text[0].lower() == 'admin':
                if channel_id == slack_ctf_admin_channel:
                    slack_ack(url, "Hey, _CTF commando_, access is being provisioned!")
                    print(f"Provisioning access to env: {input_text[1]} for: {input_text[2]} as requested by: {requestor_name}")
                    http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-admin"
                    access_payload = {
                        "env_name": input_text[1],
                        "user_email": input_text[2],
                        "action": "Grant"
                    }
                    function_response = call_function(http_endpoint, access_payload)
                    function_response_json = function_response.json()
                    
                    # compose message to respond back to the caller
                    slack_message = [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": function_response_json['info']
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*User Email:*\n{input_text[2]}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Env Name:*\n{input_text[1]}"
                                }
                            ]
                        },
                        {
                            "type": "actions",
                            "elements": []
                        }
                    ]

                    if function_response_json['info'] == "Grant: Successful":
                        slack_message[2]['elements'].append({
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "emoji": True,
                                "text": "Revoke"
                            },
                            "style": "danger",
                            "value": f"type=admin+env_name={input_text[1]}+user_email={input_text[2]}+action=Revoke",
                            "confirm": {
                                "title": {
                                    "type": "plain_text",
                                    "text": "Are you sure?"
                                },
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"Do you want to revoke access for {input_text[2]}?"
                                },
                                "confirm": {
                                    "type": "plain_text",
                                    "text": "Yes, revoke!"
                                },
                                "deny": {
                                    "type": "plain_text",
                                    "text": "Stop, I've changed my mind!"
                                }
                            }
                        })

                    return post_slack_message(slack_ctf_admin_channel, function_response_json['info'], slack_message)
                else:
                    print(f"{requestor_name} is unauthorized to execute CTF admin commands.")
                    return {
                        "response_type": "ephemeral",
                        "type": "mrkdwn",
                        "text": f"You are unauthorized to execute CTF admin commands.\nPing <@{slack_admin}> for any help."
                    }
            elif input_text[0].lower() == 'game' and input_text[1].lower() == 'create':
                if requestor_id == slack_admin:
                    slack_ack(url, "Hey, _CTF commando_, game is being created!")
                    print(f"Creating new game: {input_text[2]} as requested by: {requestor_name}")
                    http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-game"
                    game_payload = {
                        "game_name": input_text[2],
                        "action": "Create"
                    }
                    function_response = call_function(http_endpoint, game_payload)
                    function_response_json = function_response.json()
                    
                    # compose message to respond back to the caller
                    slack_message = [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Game: {input_text[2]}"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": function_response_json['info']
                                }
                            ]
                        }
                    ]

                    if function_response_json['info'] == "Create: Successful":
                        slack_message.append({
                            "type": "actions",
                            "elements": []
                        })
                        buttons = ["Start", "End"]
                        for button in buttons:
                            slack_message[2]['elements'].append({
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "emoji": True,
                                    "text": button
                                },
                                "style": "danger" if button == "End" else "primary",
                                "value": f"type=game+game_name={input_text[2]}+action={button}",
                                "confirm": {
                                    "title": {
                                        "type": "plain_text",
                                        "text": "Are you sure?"
                                    },
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"Do you want to {button} the Game: {input_text[2]}?"
                                    },
                                    "confirm": {
                                        "type": "plain_text",
                                        "text": f"Yes, {button} it!"
                                    },
                                    "deny": {
                                        "type": "plain_text",
                                        "text": "Stop, I've changed my mind!"
                                    }
                                }
                            })

                    return post_slack_message(slack_ctf_admin_channel, function_response_json['info'], slack_message)
                else:
                    print(f"{requestor_name} is unauthorized to execute CTF game commands.")
                    return {
                        "response_type": "ephemeral",
                        "type": "mrkdwn",
                        "text": f"You are unauthorized to execute CTF game commands.\nPing <@{slack_admin}> for any help."
                    }
            elif input_text[0].lower() == 'player' and input_text[1].lower() == 'start':
                slack_ack(url, "Hey, _CTF commando_, you're being enrolled!")
                print(f"Enrolling player: {requestor_name}, {requestor_id} in game: {input_text[2]}")
                http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-player"
                player_payload = {
                    "player_name": requestor_name,
                    "player_id": requestor_id,
                    "game_name": input_text[2],
                    "action": "Enroll"
                }
                function_response = call_function(http_endpoint, player_payload)
                function_response_json = function_response.json()
                
                # compose message to respond back to the player
                display_text = function_response_json['info']
                if not function_response_json['info'].startswith("This"):
                    display_text += f"\nPing <@{slack_admin}> for any help."

                slack_message = [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"Welcome to the Security CTF: {input_text[2]}"
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
                                "text": display_text
                            }
                        ]
                    }
                ]

                if function_response_json['info'].startswith("This"):
                    slack_message.append({
                        "type": "actions",
                        "elements": [{
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "emoji": True,
                                "text": "Play"
                            },
                            "style": "primary",
                            "value": f"type=player+game_name={input_text[2]}+action=serve+challenge_id=ch01",
                            "confirm": {
                                "title": {
                                    "type": "plain_text",
                                    "text": "Are you sure?"
                                },
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"Once you begin, there's no looking back!"
                                },
                                "confirm": {
                                    "type": "plain_text",
                                    "text": "Yes, bring it on!"
                                },
                                "deny": {
                                    "type": "plain_text",
                                    "text": "Stop, I've changed my mind!"
                                }
                            }
                        }]
                    })
                elif function_response_json['info'].startswith("Serve"):
                    slack_message.append({
                        "type": "actions",
                        "elements": [{
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "emoji": True,
                                "text": function_response_json['info']
                            },
                            "style": "primary",
                            "value": f"type=player+game_name={input_text[2]}+action=serve+challenge_id=ch{function_response_json['info'][-2:]}"
                        }]
                    })

                return post_slack_message(requestor_id, function_response_json['info'], slack_message)
            else:
                print("Invalid action invoked")
                return {
                    "response_type": "ephemeral",
                    "type": "mrkdwn",
                    "text": "Invalid slash command. Please use /ctf `player` and so on..."
                }
        elif payload.startswith("payload="):
            # handling the response action
            response_json = json.loads(urllib.parse.unquote(payload.split("payload=")[1]))
            value = response_json['actions'][0]['value']
            print(value)
            action_type = value.split("type=")[1].split("+")[0]
            action = value.split("action=")[1].split("+")[0]

            if action_type == "admin" and action == "Revoke":
                env_name = value.split("env_name=")[1].split("+")[0]
                user_email = value.split("user_email=")[1].split("+")[0]
            
                slack_ack(response_json['response_url'], "Hey, _CTF commando_, access is being revoked!")
                print(f"Revoking access to env: {env_name} for: {user_email} as requested by: {response_json['user']['name']}")
                
                http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-admin"
                access_payload = {
                    "env_name": env_name,
                    "user_email": user_email,
                    "action": action
                }
                function_response = call_function(http_endpoint, access_payload)
                function_response_json = function_response.json()
    
                # compose message to respond back to the caller
                slack_message = {
                    "text": "Access Revocation!",
                    "blocks": [ 
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": function_response_json['info']
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
                                    "text": f"*User Email:*\n{user_email}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Env Name:*\n{env_name}"
                                }
                            ]
                        }
                    ]
                }
                return post_slack_response(response_json['response_url'], slack_message)
            elif action_type == "game":
                game_name = value.split("game_name=")[1].split("+")[0]
                
                slack_ack(response_json['response_url'], f"Hey, _CTF commando_, game is being {action}ed!")
                print(f"{action}ing Game: {game_name} as requested by: {response_json['user']['name']}")
                
                http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-game"
                game_payload = {
                    "game_name": game_name,
                    "action": action
                }
                function_response = call_function(http_endpoint, game_payload)
                function_response_json = function_response.json()
    
                # compose message to respond back to the caller
                slack_message = {
                    "text": f"Game: {game_name} {action}ed!",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Game: {game_name}"
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
                                    "text": function_response_json['info']
                                }
                            ]
                        }
                    ]
                }
                if action == "Start":
                    slack_message['blocks'].append({
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "emoji": True,
                                    "text": "End"
                                },
                                "style": "danger",
                                "value": f"type=game+game_name={game_name}+action=End",
                                "confirm": {
                                    "title": {
                                        "type": "plain_text",
                                        "text": "Are you sure?"
                                    },
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"Do you want to end the game: {game_name}?"
                                    },
                                    "confirm": {
                                        "type": "plain_text",
                                        "text": f"Yes, kill it!"
                                    },
                                    "deny": {
                                        "type": "plain_text",
                                        "text": "Stop, I've changed my mind!"
                                    }
                                }
                            }
                        ]
                    })
                return post_slack_response(response_json['response_url'], slack_message)
            ################### process response and compute score ###################
            elif action_type == "player" and action == "play":
                game_name = value.split("game_name=")[1].split("+")[0]
                option_id = value.split("option_id=")[1].split("+")[0]
                challenge_id = value.split("challenge_id=")[1].split("+")[0]
                
                slack_ack(response_json['response_url'], "Hey, _CTF commando_, your request is being actioned!")
                print(f"{action}ing Game: {game_name} as requested by: {response_json['user']['name']}")
                
                http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-player"
                player_payload = {
                    "player_id": response_json['user']['id'],
                    "game_name": game_name,
                    "action": action,
                    "option_id": option_id,
                    "challenge_id": challenge_id,
                    "response_url": response_json['response_url']
                }
                response = call_function(http_endpoint, player_payload)
                return {
                    'statusCode': response.status_code
                }
            ################### serve challenge with or without hint ###################
            elif (action_type == "player") and (action == "hint" or action == "serve"):
                game_name = value.split("game_name=")[1].split("+")[0]
                challenge_id = value.split("challenge_id=")[1].split("+")[0]
                
                slack_ack(response_json['response_url'], "Hey, _CTF commando_, your challenge is being served!")
                print(f"{action}ing Game: {game_name} as requested by: {response_json['user']['name']}")
                
                http_endpoint = f"https://{deployment_region}-{deployment_project}.cloudfunctions.net/security-ctf-player"
                player_payload = {
                    "player_id": response_json['user']['id'],
                    "game_name": game_name,
                    "action": action,
                    "challenge_id": challenge_id,
                    "response_url": response_json['response_url']
                }
                response = call_function(http_endpoint, player_payload)
                return {
                    'statusCode': response.status_code
                }
        else:
            print("Not a valid payload!")
            return {
                'statusCode': 200,
                'body': json.dumps("Not a valid payload!")
            }
    else:
        print("Unauthorized request!")
        return {
            'statusCode': 401,
            'body': json.dumps("Unauthorized request!")
        }

def verify_request(timestamp,payload,slack_signature,slack_signing_secret):
    # Check that the request is no more than 60 seconds old
    if (int(time.time()) - int(timestamp)) > 60:
        print("Verification failed. Request is out of date.")
        return False
    else:
        sig_basestring = ('v0:' + timestamp + ':' + payload)
        my_signature = 'v0=' + hmac.new(slack_signing_secret.encode('utf-8'), sig_basestring.encode('utf-8'), hashlib.sha256).hexdigest()
        if my_signature == slack_signature:
            print("Verification succeeded. Signature valid.")
            return True
        else:
            print("Verification failed. Signature invalid.")
            return False

def call_function(http_endpoint, response_payload):
    auth_req = google.auth.transport.requests.Request()
    id_token = google.oauth2.id_token.fetch_id_token(auth_req, http_endpoint)
    
    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"
    headers["Authorization"] = f"Bearer {id_token}"
    headers["Content-Type"] = "application/json"

    return requests.post(http_endpoint, json=response_payload, headers=headers)

def slack_ack(url, ack_text):
    ack_message = {
        "response_type": "ephemeral",
        "type": "mrkdwn",
        "text": ack_text
    }
    response = requests.post(url, data=json.dumps(ack_message), headers={'Content-Type': 'application/json'})
    print(f"Slack responded with Status Code: {response.status_code}")

def post_slack_message(slack_channel, slack_text, slack_message):
    slack_token = os.environ.get('SLACK_ACCESS_TOKEN', 'Specified environment variable is not set.')
    response = requests.post("https://slack.com/api/chat.postMessage", data={
        "token": slack_token,
        "channel": slack_channel,
        "text": slack_text,
        "blocks": json.dumps(slack_message)
    })
    print(f"Message posted - Slack responded with Status Code: {response.status_code}")
    return {
        'statusCode': response.status_code
    }

def post_slack_response(url, slack_message):
    response = requests.post(url, data=json.dumps(slack_message), headers={'Content-Type': 'application/json'})
    print(f"Message posted - Slack responded with Status Code: {response.status_code}")
    return {
        'statusCode': response.status_code
    }