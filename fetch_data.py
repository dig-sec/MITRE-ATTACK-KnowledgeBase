import os
import requests

# URLs of the files
json_url = "https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json"
csv_url = "https://raw.githubusercontent.com/sduff/mitre_attack_csv/main/enterprise-attack.csv"

# Path to the data folder
data_folder = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(data_folder, exist_ok=True)

# Paths to save the files
json_file_path = os.path.join(data_folder, 'attack_rule_map.json')
csv_file_path = os.path.join(data_folder, 'enterprise-attack.csv')

# Function to fetch and save a file
def fetch_and_save_file(url, file_path):
    if os.path.exists(file_path):
        print(f"File already exists: {file_path}")
        return
    response = requests.get(url)
    if response.status_code == 200:
        with open(file_path, 'wb') as file:
            file.write(response.content)
        print(f"File saved to {file_path}")
    else:
        print(f"Failed to fetch the file from {url}. Status code: {response.status_code}")

# Fetch and save the JSON file
fetch_and_save_file(json_url, json_file_path)

# Fetch and save the CSV file
fetch_and_save_file(csv_url, csv_file_path)
