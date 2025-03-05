import os
import json
import base64
import random
import string
from google.cloud import storage

def serverless_security(request):
     
     event = json.loads(request.get_data().decode('UTF-8'))
     print("Writing a token to the given bucket...")
     try:
          # Declare environment variables
          project_name   = os.environ.get('PROJECT_NAME')
          token_bucket   = os.environ.get('TOKEN_BUCKET')
          token_object   = os.environ.get('TOKEN_OBJECT')
     
          # Create a Storage client
          storage_client = storage.Client(project=project_name)

          # Get the bucket and object handles
          bucket_handle = storage_client.bucket(token_bucket)
          object_handle = bucket_handle.blob(token_object)

          # Generate a random token
          length = 8
          secure_token = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
          print(secure_token)
    
          # Upload the error message to the bucket
          object_handle.upload_from_string(secure_token)
    
     except Exception as e:
          raise RuntimeError(f"Could not write secure token to bucket: {e}")
