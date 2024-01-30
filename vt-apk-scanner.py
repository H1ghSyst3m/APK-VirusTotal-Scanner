import os
import requests
import time
import json
import hashlib
import itertools

# List of VirusTotal API keys
API_KEYS = ['API_KEY1', 'API_KEY2', 'API_KEY3', 'API_KEY4', 'API_KEY5', 'API_KEY6']

# Name of the Subfolder
subfolder_name = 'apk'

# Combine the actual path with the subfolder
folder_path = os.path.join(os.getcwd(), subfolder_name)

# VirusTotal API URLs
upload_url = 'https://www.virustotal.com/api/v3/files'
analysis_url = 'https://www.virustotal.com/api/v3/analyses/'
file_search_url = 'https://www.virustotal.com/api/v3/files/'

# Function to generate the hash of a file
def get_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Function to extract relevant information from VirusTotal results
def extract_vt_info(vt_result, file_hash, filename):
    # Initialize result info with basic data
    result_info = {
        'filename': filename,
        'hash': file_hash,
        'link': 'https://www.virustotal.com/gui/file/' + file_hash,
        'scan_date': None,
        'positives': None,
        'total': None,
        'file_type': None,
        'file_size': None,
        'detected_by': {}
    }

    # Check if the necessary keys are present
    attributes = vt_result.get('data', {}).get('attributes', {})
    if 'last_analysis_date' in attributes:
        result_info['scan_date'] = attributes['last_analysis_date']
    if 'last_analysis_stats' in attributes:
        result_info['positives'] = attributes['last_analysis_stats'].get('malicious', 0)
        result_info['total'] = attributes['last_analysis_stats'].get('undetected', 0) + \
                               attributes['last_analysis_stats'].get('malicious', 0)
    if 'type_description' in attributes:
        result_info['file_type'] = attributes['type_description']
    if 'size' in attributes:
        result_info['file_size'] = attributes['size']

    # Extract details of detected threats if available
    detections = attributes.get('last_analysis_results', {})
    for av, av_result in detections.items():
        if av_result.get('category') == 'malicious':
            result_info['detected_by'][av] = av_result.get('result')

    return result_info

# Function to check if a file has already been scanned on VirusTotal
def check_file_in_virustotal(file_hash, headers):
    response = requests.get(file_search_url + file_hash, headers=headers)
    if response.status_code == 200:
        return json.loads(response.text)
    return None

# Function to upload a file to VirusTotal and get the analysis ID
def upload_file(file_path, headers):
    with open(file_path, 'rb') as file:
        files = {'file': (os.path.basename(file_path), file)}
        response = requests.post(upload_url, headers=headers, files=files)
        return json.loads(response.text)['data']['id']

# Function to get the analysis result from VirusTotal
def get_analysis_result(analysis_id, headers):
    while True:
        result_url = analysis_url + analysis_id
        response = requests.get(result_url, headers=headers)
        result = json.loads(response.text)

        # Check the analysis status
        status = result['data']['attributes']['status']
        if status == 'completed':
            return result
        elif status in ['queued', 'in-progress']:
            print(f"Analysis is {status}, waiting for 5 seconds...")
            time.sleep(5)

# Function to save results to file
def save_results(results):
    with open('virus_total_results.json', 'w') as result_file:
        json.dump(results, result_file, indent=4)

# Function to upload a file to VirusTotal without triggering analysis
def upload_file_only(file_path, headers):
    with open(file_path, 'rb') as file:
        files = {'file': (os.path.basename(file_path), file)}
        response = requests.post(upload_url, headers=headers, files=files)
        if response.status_code == 200:
            return json.loads(response.text)['data']['id']
        return None

# Function to request a reanalyse
def request_reanalysis(file_hash, headers):
    reanalysis_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
    response = requests.post(reanalysis_url, headers=headers)
    if response.status_code == 200:
        print(f"Reanalysis requested for file {file_hash}")
    else:
        print(f"Failed to request reanalysis for file {file_hash}, status code: {response.status_code}")

# Main script
def main():
    # Check if folder exists
    if not os.path.exists(folder_path):
        print("The folder does not exist. Please check the path.")
        return

    # Load existing results if available
    existing_results = []
    if os.path.exists('virus_total_results.json'):
        with open('virus_total_results.json', 'r') as result_file:
            try:
                existing_results = json.load(result_file)
            except json.JSONDecodeError:
                existing_results = []

    # Extract existing hashes
    existing_hashes = {result['hash'] for result in existing_results}

    api_keys_iterator = itertools.cycle(API_KEYS)
    api_keys_available = set(API_KEYS)
    uploaded_count = 0
    start_time = time.time()
    files_to_process = os.listdir(folder_path)

    # Process each file in the folder
    while files_to_process:
        file = files_to_process[0]  # Get the first file from the list
        file_path = os.path.join(folder_path, file)

        # Check if we need to rate limit
        current_time = time.time()
        if uploaded_count >= 8 and (current_time - start_time) < 60:
            time_to_wait = 60 - (current_time - start_time)
            print(f"Rate limit reached, waiting for {time_to_wait} seconds...")
            time.sleep(time_to_wait)
            uploaded_count = 0
            start_time = time.time()

        if os.path.isfile(file_path) and file_path.endswith('.apk'):
            file_hash = get_file_hash(file_path)
            if file_hash in existing_hashes:
                print(f"{file} has already been analyzed. Skipping...")
                files_to_process.pop(0)  # Remove the processed file from the list
                continue

            api_key = next(api_keys_iterator)
            while api_key not in api_keys_available:
                api_key = next(api_keys_iterator)

            headers = {'x-apikey': api_key}

            # Check if file has been scanned on VirusTotal
            vt_result = check_file_in_virustotal(file_hash, headers)
            if vt_result:
                print(f"{file} has already been scanned on VirusTotal. Retrieving result...")
                extracted_info = extract_vt_info(vt_result, file_hash, file)
                if extracted_info['total'] is not None and extracted_info['total'] < 60:
                    request_reanalysis(file_hash, headers)
                    files_to_process.pop(0)  # Remove the file and skip further processing
                    continue
                existing_results.append(extracted_info)
                files_to_process.pop(0)  
            else:
                print(f"Attempting to upload {file} using API Key: {api_key}...")
                upload_id = upload_file_only(file_path, headers)
                if upload_id:
                    print(f"File {file} uploaded successfully, ID: {upload_id}")
                    uploaded_count += 1
                    files_to_process.pop(0)  # Remove the processed file from the list
                else:
                    print(f"Error or rate limit for API key {api_key}, switching to next key.")
                    api_keys_available.discard(api_key)
                    if not api_keys_available:
                        print("All API keys have reached their rate limits. Exiting.")
                        break

            # Save results after each operation
            save_results(existing_results)

            # Short wait before processing the next file
            time.sleep(0)

    print("Operation complete. All results are saved in 'virus_total_results.json'.")

# Execute the script
if __name__ == '__main__':
    main()
