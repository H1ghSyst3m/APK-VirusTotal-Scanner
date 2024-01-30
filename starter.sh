#!/bin/bash

# Print a message
echo "Run git-downloader.py..."
# Execute the git-downloader.py script
python git-downloader.py

# Print a message
echo "Run vt-apk-scanner.py..."
# Execute the vt-apk-scanner.py script
python vt-apk-scanner.py

# Print a message
echo "All Scripts done."
# Wait for user input before closing
read -p "Press any key to continue..."
