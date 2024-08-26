import os
import functions_framework
from flask import jsonify
from google.cloud import dlp

# create a dlp client for this project
dlp_client = dlp.DlpServiceClient()

# read os environment variables
KMS_KEY       = os.environ.get('KMS_KEY')
WRAPPED_KEY   = os.environ.get('WRAPPED_KEY')
PROJECT_NAME  = os.environ.get('PROJECT_NAME')
parent        = f"projects/{PROJECT_NAME}"

def aadhaar_vault(request):
  try:
    request_json  = request.get_json()
    mode          = request_json['mode']
    strings       = request_json['strings']
    if mode == "tokenize":
        return tokenize(strings)
    elif mode == "detokenize":
        return detokenize(strings)
  except Exception as e:
    return jsonify( { "errorMessage": str(e) } ), 400

def tokenize(strings):
  # The infoTypes of information to match
  INFO_TYPES = ['US_SOCIAL_SECURITY_NUMBER']
  inspect_config = {"info_types": [{"name": info_type} for info_type in INFO_TYPES]}
  deidentify_config = {
    "info_type_transformations": {
      "transformations": [
        {
          "info_types": [{"name": info_type} for info_type in INFO_TYPES],
          "primitive_transformation": {
            "crypto_deterministic_config": {
              "crypto_key": {
                "kms_wrapped": {
                  "crypto_key_name": KMS_KEY,
                  "wrapped_key": WRAPPED_KEY
                }
              },
              "surrogate_info_type": {
                "name": "TOKENIZED_VALUE"
              }
            }
          }
        }
      ]
    }
  }

  return_value = []
  for string in strings:
    response_text = dlp_client.deidentify_content(
      request={
          "parent": parent,
          "deidentify_config": deidentify_config,
          "inspect_config": inspect_config,
          "item": {"value": string[0]},
      }
    )
    return_value.append(response_text.item.value)
  return jsonify( { "replies":  return_value } )

def detokenize(strings):
  # The infoTypes of information to match
  inspect_config = {"custom_info_types": [{"info_type": {"name": "TOKENIZED_VALUE"},"surrogate_type": {}}]}
  reidentify_config = {
    "info_type_transformations": {
      "transformations": [
        {
          "info_types": [{"name": "TOKENIZED_VALUE"}],
          "primitive_transformation": {
            "crypto_deterministic_config": {
              "crypto_key": {
                "kms_wrapped": {
                  "crypto_key_name": KMS_KEY,
                  "wrapped_key": WRAPPED_KEY
                }
              },
              "surrogate_info_type": {
                "name": "TOKENIZED_VALUE"
              }
            }
          }
        }
      ]
    }
  }

  return_value = []
  for string in strings:
    response_text = dlp_client.reidentify_content(
      request={
          "parent": parent,
          "reidentify_config": reidentify_config,
          "inspect_config": inspect_config,
          "item": {"value": string[0]},
      }
    )
    return_value.append(response_text.item.value)
  return jsonify( { "replies":  return_value } )