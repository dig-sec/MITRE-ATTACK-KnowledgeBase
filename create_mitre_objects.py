import os
import json
import time
import logging
import pandas as pd
import requests
import yaml
from dataclasses import dataclass
from typing import Optional, List, Dict

@dataclass
class TechniqueData:
    id: str
    name: str
    description: str
    platforms: str
    kill_chain_phases: str
    data_sources: str
    detection: str
    url: Optional[str] = None

class Config:
    # Default configuration values are hardcoded here
    DATA_DIR: str = "data"
    MITRE_CSV_PATH: str = os.path.join("data", "enterprise-attack.csv")
    ATTACK_RULE_MAP_PATH: str = os.path.join("data", "attack_rule_map.json")
    OUTPUT_DIR: str = "MITRE_ATT&CK_Analysis"
    CYCAT_BASE_URL: str = "https://api.cycat.org"
    ATOMICS_DIR: str = os.path.join("data", "atomics")

def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler("mitre_object_creator.log"), logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

class MITREDataManager:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
    def read_csv(self) -> pd.DataFrame:
        if not os.path.exists(Config.MITRE_CSV_PATH):
            raise FileNotFoundError(f"CSV not found at {Config.MITRE_CSV_PATH}")
        df = pd.read_csv(
            Config.MITRE_CSV_PATH,
            quotechar='"',
            doublequote=True,
            escapechar='\\',
            on_bad_lines='warn'
        )
        df.columns = [col.strip().lower() for col in df.columns]
        df = df.fillna({
            'platforms': '',
            'kill chain phases': '',
            'data sources': '',
            'detection': 'No detection information available'
        })
        self.logger.info(f"Loaded {len(df)} techniques")
        return df

def load_attack_rule_map(logger: logging.Logger) -> List[Dict]:
    try:
        with open(Config.ATTACK_RULE_MAP_PATH, "r", encoding="utf-8") as f:
            attack_rule_map = json.load(f)
        logger.info("Loaded attack rule map.")
        return attack_rule_map
    except Exception as e:
        logger.error(f"Error loading attack rule map: {e}")
        return []

def get_attack_rule_map_for_technique(technique_id: str, attack_rule_map: List[Dict], logger: logging.Logger) -> List[Dict]:
    matching_rules = [entry for entry in attack_rule_map if entry.get("tech_id") == technique_id]
    
    for entry in matching_rules:
        sigma_rules = entry.get("sigma_rules", [])
        for sigma_rule in sigma_rules:
            rule_link = sigma_rule.get("rule_link")
            if rule_link:
                if rule_link.startswith("https://github.com/SigmaHQ/sigma/blob/master/"):
                    rule_link = rule_link.replace(
                        "https://github.com/SigmaHQ/sigma/blob/master/",
                        "https://raw.githubusercontent.com/SigmaHQ/sigma/refs/heads/master/"
                    )
                try:
                    response = requests.get(rule_link, timeout=10)
                    if response.status_code == 200:
                        sigma_rule["remote_content"] = response.text
                    else:
                        sigma_rule["remote_content"] = f"Failed to fetch content: HTTP {response.status_code}"
                except Exception as e:
                    sigma_rule["remote_content"] = f"Error fetching content: {e}"
    return matching_rules

def cycat_enrich(technique: TechniqueData, logger: logging.Logger) -> Dict:
    url = f"{Config.CYCAT_BASE_URL}/namespace/finduuid/mitre-attack-id/{technique.id}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                uuids = data.get("cycat_related_uuids", [])
            elif isinstance(data, list):
                uuids = data
            else:
                uuids = []
            lookup_results = []
            for uuid in uuids:
                lookup_url = f"{Config.CYCAT_BASE_URL}/lookup/{uuid}"
                try:
                    lookup_response = requests.get(lookup_url, timeout=10)
                    if lookup_response.status_code == 200:
                        lookup_results.append({
                            "uuid": uuid,
                            "lookup_data": lookup_response.json()
                        })
                    else:
                        lookup_results.append({
                            "uuid": uuid,
                            "lookup_data": f"Failed to fetch: HTTP {lookup_response.status_code}"
                        })
                except Exception as e:
                    lookup_results.append({
                        "uuid": uuid,
                        "lookup_data": f"Error fetching lookup: {e}"
                    })
            return {"cycat": {"cycat_related_uuids": uuids, "lookup_results": lookup_results}}
        else:
            logger.error(f"CyCAT API error: HTTP {response.status_code}")
    except Exception as e:
        logger.error(f"CyCAT API error: {e}")
    return {"error": "Failed to enrich technique via CyCAT"}

def get_atomics_for_technique(technique_id: str, logger: logging.Logger) -> List[Dict]:
    """
    Walk through the atomics directory and load any YAML file whose content includes
    a matching 'attack_technique' value for the given technique_id.
    """
    atomics_list = []
    atomics_dir = Config.ATOMICS_DIR
    if not os.path.exists(atomics_dir):
        logger.error(f"Atomics directory not found: {atomics_dir}")
        return atomics_list

    for root, dirs, files in os.walk(atomics_dir):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        # Check for a single atomic test defined at the root
                        if "attack_technique" in data and data["attack_technique"] == technique_id:
                            atomics_list.append(data)
                        # Check if the file contains multiple atomic tests under "atomic_tests"
                        elif "atomic_tests" in data and isinstance(data["atomic_tests"], list):
                            for test in data["atomic_tests"]:
                                if isinstance(test, dict) and test.get("attack_technique") == technique_id:
                                    atomics_list.append(test)
                                    break
                except Exception as e:
                    logger.error(f"Error reading atomics file {file_path}: {e}")
    return atomics_list

def enrich_technique(technique: TechniqueData, attack_rule_map: List[Dict], logger: logging.Logger) -> Dict:
    attack_rules = get_attack_rule_map_for_technique(technique.id, attack_rule_map, logger)
    cycat_data = cycat_enrich(technique, logger)
    atomics_data = get_atomics_for_technique(technique.id, logger)
    return {"attack_rule_map": attack_rules, "cycat": cycat_data, "atomics": atomics_data}

def main():
    logger = setup_logging()

    data_manager = MITREDataManager(logger)
    try:
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
        df = data_manager.read_csv()

        # Load the global attack rule map once.
        attack_rule_map = load_attack_rule_map(logger)

        for idx, row in df.iterrows():
            technique = TechniqueData(
                id = str(row.get("id", "")).strip(),
                name = str(row.get("name", "")).strip(),
                description = str(row.get("description", "")).strip(),
                platforms = str(row.get("platforms", "")).strip(),
                kill_chain_phases = str(row.get("kill chain phases", "")).strip(),
                data_sources = str(row.get("data sources", "")).strip(),
                detection = str(row.get("detection", "")).strip(),
                url = str(row.get("url", "")).strip()
            )
            if not technique.id or not technique.name:
                logger.error("Missing ID or name, skipping technique.")
                continue

            file_path = os.path.join(Config.OUTPUT_DIR, f"{technique.id}.json")
            if os.path.exists(file_path):
                logger.info(f"Technique {technique.id} already processed. Skipping.")
                continue

            enrichments = enrich_technique(technique, attack_rule_map, logger)

            full_data = {
                **technique.__dict__,
                "enrichments": enrichments,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(full_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Saved enriched technique {technique.id}")
        logger.info("All techniques processed.")
    except Exception as e:
        logger.error(f"Error processing CSV: {e}")

if __name__ == "__main__":
    main()