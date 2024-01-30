import os
import shutil
from git import Repo

# Define paths
github_repo_url = 'https://github.com/keiyoushi/extensions.git'
subfolder_extensions = 'extensions'
local_repo_path = os.path.join(os.getcwd(), subfolder_extensions)
subfolder_apk = 'apk'
apk_folder_path = os.path.join(os.getcwd(), subfolder_apk)

# Clone the GitHub repository or update it if it already exists
if not os.path.isdir(local_repo_path):
    Repo.clone_from(github_repo_url, local_repo_path)
else:
    repo = Repo(local_repo_path)
    fetched_info = repo.remotes.origin.pull()

# Check whether new changes have been fetched
if fetched_info[0].flags > 4:  # Check whether new commits have been fetched
    print("New updates found and downloaded.")
else:
    print("No new updates available.")

# Path to the APK folder in the repository
repo_apk_path = os.path.join(local_repo_path, 'apk')

# Create a list of all APKs in the local folder
local_apks = set(os.listdir(apk_folder_path))

# Count the number of APKs before the update
initial_apk_count = len(local_apks)

# Check which APKs are present in the repository folder but not in the local folder
added_count = 0
for file in os.listdir(repo_apk_path):
    if file.endswith('.apk') and file not in local_apks:
        shutil.copy2(os.path.join(repo_apk_path, file), apk_folder_path)
        added_count += 1
        print(f'APK added: {file}')

# Count the number of APKs after the update
final_apk_count = len(os.listdir(apk_folder_path))

# Display informations
print(f'Number of APKs before the update: {initial_apk_count}')
print(f'Number of APKs added: {added_count}')
print(f'Number of APKs after the update: {final_apk_count}')
print(f' ')
print(f'----------------------------------------------------------------')
print(f' ')
