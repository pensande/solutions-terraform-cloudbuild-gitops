import json
import base64
import boto3
from botocore.credentials import WebIdentityProvider

# Constants
SOCKET_PATH = "/run/container_launcher/teeserver.sock"
TOKEN_ENDPOINT = "http://localhost/v1/token"
CONTENT_TYPE = "application/json"
AUDIENCE = "https://meal.corp"
ROLE_ARN = "arn:aws:iam::882493070157:role/confidential-space-role"
AWS_KMS_KEY_ID = "98ac6406-43e1-488c-b9ae-6fee66d13c4a"
TOKEN_PATH = "./token"
TOKEN_TYPE = "LIMITED_AWS"
AWS_REGION = "eu-west-1"
AWS_SESSION_NAME = "integration_test"
BUCKET_NAME = "confidential-space-bucket"
OBJECT_KEY = "primus_customer_list_enc"

# Function to get a custom token
def get_custom_token(body):
    import requests
    import socket

    # Use requests library for HTTP communication
    response = requests.post(
        TOKEN_ENDPOINT,
        headers={"Content-Type": CONTENT_TYPE},
        data=json.dumps(body),
    )

    response.raise_for_status()  # Raise an exception for bad status codes
    return response.text

# Function to write token to file
def write_token_to_path(token, token_path):
    with open(token_path, "w") as f:
        f.write(token)

# Function to fetch blob from S3
def fetch_blob_from_s3(session, provider):
    # Use boto3 for AWS interaction
    s3_client = session.client('s3', config=provider)
    try:
        # List objects in the bucket
        objects = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        for obj in objects['Contents']:
            print(f"Object Key: {obj['Key']}")
        
        # Read the encrypted object from S3
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=obj['Key'])
        ciphertext_blob = base64.b64decode(response['Body'].read())

        # Return the ciphertext blob
        return ciphertext_blob
    except Exception as e:
        print(f"Error reading objects: {e}")

def main():
    # Get LIMITED_AWS token
    body = {
        "audience": AUDIENCE,
        "token_type": TOKEN_TYPE,
    }

    token = get_custom_token(body)
    print(f"Token received: {token}")

    # AWS Module requires a token path for some reason
    write_token_to_path(token, TOKEN_PATH)

    # Create a boto3 session
    session = boto3.Session(region_name=AWS_REGION)

    # Create a WebIdentityProvider
    provider = WebIdentityProvider(
        role_arn=ROLE_ARN,
        web_identity_token_path=TOKEN_PATH,
        client=session.client('sts'),
        session_name=AWS_SESSION_NAME,
    )

    # Download data from AWS
    blob_from_s3 = fetch_blob_from_s3(session, provider)

    try:
        # Call Decrypt
        kms_client = session.client('kms', config=provider)
        decrypted_result = kms_client.decrypt(
            KeyId=AWS_KMS_KEY_ID,
            CiphertextBlob=blob_from_s3,
        )

        # Decode the plaintext from bytes to string
        plaintext = decrypted_result['Plaintext'].decode('utf-8')

        print(f"Decrypt Succeeded: {plaintext}")
    except Exception as e:
        print(f"Error decrypting object: {e}")
        return None

if __name__ == "__main__":
    print("-" * 88)
    print(f"Welcome to the IAM create user and assume role demo.")
    print("-" * 88)
    try:
        main()
    except Exception:
        print("Something went wrong!")
    finally:
        print("Thanks for watching!")