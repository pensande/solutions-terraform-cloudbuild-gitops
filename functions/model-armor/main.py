import os
import csv
import json
from google.cloud import firestore
from google.cloud import storage
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

# declare environment variables
PROJECT_ID = os.environ.get('PROJECT_ID')
LOCATION_ID = os.environ.get('LOCATION_ID')
TEMPLATE_ID = os.environ.get('TEMPLATE_ID')

# create clients
storage_client = storage.Client(project=PROJECT_ID)

print("Creating Model Armor client...")
client = modelarmor_v1.ModelArmorClient(
    transport="rest",
    client_options=ClientOptions(
        api_endpoint=f"modelarmor.{LOCATION_ID}.rep.googleapis.com"
    ),
)
print("Model Armor client created!")

def model_armor(event, context):
    """Triggered by a change to a Cloud Storage bucket.
    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    print(f"Processing file: {event['name']}.")

    try:
        mybucket = storage_client.get_bucket(event['bucket'])
        blob = mybucket.get_blob(event['name'])
        
        if event['contentType']=='text/csv':
            csvfile = blob.download_as_bytes()
            csvcontent = csvfile.decode('utf-8').splitlines()
            lines = csv.reader(csvcontent)
            
            header = 0
            data = {}
            db = firestore.Client(project=PROJECT_ID)

            for line in lines:
                if header == 0:
                    header_row = line
                    header += 1
                else:
                    index = 0
                    for column in line:
                        if index == 0:
                            document_id = column 
                        elif index == 1:
                            data[header_row[index]] = column
                            data[header_row[index+1]], data[header_row[index+2]] = sanitize_prompt(column)
                        index += 1
                    print(data)
                    db.collection("model-armor-prompts").document(document_id).set(data)
        else:
            print(f"Sorry, I cannot process the file format: {event['contentType']}!")
    
    except Exception as e:
        print(e)
        print("Input file read unsuccessful!")

def sanitize_prompt(user_prompt):
    # Initialize request argument(s).
    user_prompt_data = modelarmor_v1.DataItem(text=user_prompt)

    # Prepare request for sanitizing the defined prompt.
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=f"projects/{PROJECT_ID}/locations/{LOCATION_ID}/templates/{TEMPLATE_ID}",
        user_prompt_data=user_prompt_data,
    )

    # Sanitize the user prompt.
    response = client.sanitize_user_prompt(request=request)

    matched_filters = ""

    for filter_name, filter_result in response.sanitization_result.filter_results.items():
        if filter_result.sdp_filter_result.inspect_result.match_state.name == "MATCH_FOUND":
            matched_filters += filter_name 
        if filter_result.rai_filter_result.match_state.name == "MATCH_FOUND":
            matched_filters += filter_name 
        if filter_result.pi_and_jailbreak_filter_result.match_state.name == "MATCH_FOUND":
            matched_filters += filter_name
        if filter_result.malicious_uri_filter_result.match_state.name == "MATCH_FOUND":
            matched_filters += filter_name
        if filter_result.csam_filter_filter_result.match_state.name == "MATCH_FOUND":
            matched_filters += filter_name

    # Return the sanitization result.
    return matched_filters, response.sanitization_result.filter_match_state.name