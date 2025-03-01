import os
import requests

# URLs of the files
attack_rule_map_url = "https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json"
enterprise_attack_csv_url = "https://raw.githubusercontent.com/sduff/mitre_attack_csv/main/enterprise-attack.csv"
enterprise_attack_json_url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"

# Path to the data folder
data_directory = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(data_directory, exist_ok=True)

# Paths to save the files
attack_rule_map_path = os.path.join(data_directory, 'attack_rule_map.json')
enterprise_attack_csv_path = os.path.join(data_directory, 'enterprise-attack.csv')
enterprise_attack_json_path = os.path.join(data_directory, 'enterprise-attack.json')

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

# Fetch and save the attack rule map JSON file
fetch_and_save_file(attack_rule_map_url, attack_rule_map_path)

# Fetch and save the enterprise attack CSV file
fetch_and_save_file(enterprise_attack_csv_url, enterprise_attack_csv_path)

# Fetch and save the enterprise attack JSON file
fetch_and_save_file(enterprise_attack_json_url, enterprise_attack_json_path)
