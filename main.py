import os
import json
import time
from typing import Any, Dict
import pandas as pd
import logging
import requests
import csv
from ollama import chat, ChatResponse


# Configuration
MITRE_CSV_URL = "https://raw.githubusercontent.com/sduff/mitre_attack_csv/main/enterprise-attack.csv"
LOCAL_CSV_PATH = "./enterprise-attack.csv"
OLLAMA_MODEL = "deepseek-r1:7b"
BASE_DIR = "MITRE_ATT&CK_Analysis"
CYCAT_BASE_URL = "https://api.cycat.org"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("mitre_emulation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

PROMPT_TEMPLATES = {
    "adversary_emulation": """
Analyze this MITRE ATT&CK technique for red team emulation:
Technique: {name}
ID: {id}
Description: {description}
Platforms: {platforms}
Data Sources: {data_sources}

Generate a detailed adversary emulation plan including:
1. Prerequisites and setup
2. Step-by-step execution procedure
3. Expected system impacts
4. Detection artifacts generated
5. Success criteria
6. Cleanup procedures

Include specific commands and tools where applicable.
Format as a structured technical analysis.
""",
    # ... [other templates remain the same]
}

def download_mitre_csv() -> bool:
    try:
        response = requests.get(MITRE_CSV_URL, timeout=30)
        if response.status_code == 200:
            # Clean and write the CSV data
            content = response.content.decode('utf-8')
            # Remove any extra newlines between records
            content = '\n'.join(line.strip() for line in content.split('\n') if line.strip())
            with open(LOCAL_CSV_PATH, "w", encoding='utf-8') as f:
                f.write(content)
            logger.info("Download complete.")
            return True
        else:
            logger.error(f"Failed to download MITRE ATT&CK CSV. Status Code: {response.status_code}")
            return False
    except requests.RequestException as e:
        logger.error(f"Download error: {e}")
        return False

def read_mitre_csv() -> pd.DataFrame:
    """
    Read the MITRE CSV file with proper handling of quoted fields and embedded commas/newlines.
    """
    try:
        # Read with pandas using the appropriate parameters for quoted fields
        df = pd.read_csv(
            LOCAL_CSV_PATH,
            quotechar='"',
            doublequote=True,
            escapechar='\\',
            on_bad_lines='warn'
        )
        
        # Clean up the column names
        df.columns = [col.strip().lower() for col in df.columns]
        
        # Handle any missing values
        df = df.fillna({
            'platforms': '',
            'kill chain phases': '',
            'data sources': '',
            'detection': 'No detection information available'
        })
        
        return df
    
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        # If pandas fails, try manual CSV parsing
        try:
            with open(LOCAL_CSV_PATH, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                data = []
                for row in reader:
                    cleaned_row = {k.strip().lower(): v.strip() for k, v in row.items()}
                    data.append(cleaned_row)
            return pd.DataFrame(data)
        except Exception as e2:
            logger.error(f"Backup CSV parsing failed: {e2}")
            raise

class OllamaEnricher:
    def __init__(self, max_retries: int = 3, retry_delay: int = 10):
        self.model = OLLAMA_MODEL
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def enrich_technique(self, technique_data: Dict[str, Any], analysis_type: str = "adversary_emulation") -> Dict[str, Any]:
        """
        Enrich the provided technique using the specified analysis type via Ollama.
        """
        prompt_template = PROMPT_TEMPLATES.get(analysis_type)
        if not prompt_template:
            logger.error(f"Analysis type '{analysis_type}' not found. Defaulting to adversary_emulation.")
            prompt_template = PROMPT_TEMPLATES["adversary_emulation"]

        prompt = prompt_template.format(**technique_data)
        retries = 0
        while retries < self.max_retries:
            try:
                response: ChatResponse = chat(model=self.model, messages=[
                    {
                        'role': 'user',
                        'content': prompt,
                    },
                ])
                result = response.message.content
                return {analysis_type: result}
            except Exception as e:
                logger.error(f"Ollama API error: {e}")
                time.sleep(self.retry_delay)
                retries += 1
        return {"error": "Failed to enrich technique via Ollama after retries"}

class CycatEnricher:
    def __init__(self, base_url: str = CYCAT_BASE_URL, max_retries: int = 3, retry_delay: int = 5):
        self.base_url = base_url
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def enrich_technique(self, technique_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich the provided technique using the CyCAT API.
        This example uses the MITRE ATT&CK technique ID to query CyCAT for related resources.
        """
        technique_id = technique_data.get("id")
        if not technique_id:
            logger.error("No technique ID provided for CyCAT enrichment.")
            return {"error": "Missing technique ID"}
        # Example endpoint: /namespace/finduuid/mitre-attack-id/{technique_id}
        url = f"{self.base_url}/namespace/finduuid/mitre-attack-id/{technique_id}"
        retries = 0
        while retries < self.max_retries:
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    # For demonstration, we assume the API returns a list of UUIDs
                    return {"cycat_related_uuids": data}
                else:
                    logger.error(f"CyCAT API error: Status Code {response.status_code}")
            except Exception as e:
                logger.error(f"CyCAT API exception: {e}")
            time.sleep(self.retry_delay)
            retries += 1
        return {"error": "Failed to enrich technique via CyCAT after retries"}

def process_technique(technique_row: pd.Series, ollama_enricher: OllamaEnricher, cycat_enricher: CycatEnricher) -> bool:
    """Process a single technique and save results with combined enrichments."""
    try:
        # Clean and validate the input data
        technique_data = {
            'name': str(technique_row.get('name', '')).strip(),
            'id': str(technique_row.get('id', '')).strip(),
            'description': str(technique_row.get('description', '')).strip(),
            'platforms': str(technique_row.get('platforms', '')).strip(),
            'kill_chain_phases': str(technique_row.get('kill chain phases', '')).strip(),
            'data_sources': str(technique_row.get('data sources', '')).strip(),
            'detection': str(technique_row.get('detection', 'No detection information available')).strip()
        }

        # Validate required fields
        if not technique_data['id'] or not technique_data['name']:
            logger.error("Missing required fields (id or name) in technique data")
            return False

        # Get enriched data from both sources
        enriched_ollama = ollama_enricher.enrich_technique(technique_data, analysis_type="adversary_emulation")
        enriched_cycat = cycat_enricher.enrich_technique(technique_data)

        full_data = {
            **technique_data,
            'enrichments': {
                'ollama': enriched_ollama,
                'cycat': enriched_cycat
            },
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'url': str(technique_row.get('url', '')).strip()  # Added URL field
        }

        # Create directories based on kill chain phases
        phases = [phase.strip() for phase in technique_data['kill_chain_phases'].split(',') if phase.strip()]
        if not phases:
            phases = ['uncategorized']

        for phase in phases:
            phase_dir = os.path.join(BASE_DIR, phase.lower().replace(' ', '_'))
            os.makedirs(phase_dir, exist_ok=True)
            file_path = os.path.join(phase_dir, f"{technique_data['id']}.json")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(full_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Processed {technique_data['id']} for phase {phase}")
        
        return True
    except Exception as e:
        logger.error(f"Error processing technique {technique_row.get('id', 'unknown')}: {e}")
        return False

def main():
    if not download_mitre_csv():
        return

    logger.info("Reading MITRE ATT&CK data from local CSV...")
    try:
        mitre_df = read_mitre_csv()
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        return

    os.makedirs(BASE_DIR, exist_ok=True)
    ollama_enricher = OllamaEnricher()
    cycat_enricher = CycatEnricher()

    success_count = 0
    total_count = len(mitre_df)

    for index, row in mitre_df.iterrows():
        if process_technique(row, ollama_enricher, cycat_enricher):
            success_count += 1
        
        # Add progress logging
        if (index + 1) % 10 == 0:
            logger.info(f"Progress: {index + 1}/{total_count} techniques processed ({(success_count/(index+1))*100:.2f}% success rate)")

    summary = {
        "total_techniques": total_count,
        "successful_processes": success_count,
        "failed_processes": total_count - success_count,
        "completion_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "success_rate": f"{(success_count/total_count)*100:.2f}%"
    }
    
    with open(os.path.join(BASE_DIR, "summary.json"), "w", encoding='utf-8') as f:
        json.dump(summary, f, indent=4, ensure_ascii=False)

    logger.info(f"Processing complete. Success rate: {(success_count/total_count)*100:.2f}%")

if __name__ == "__main__":
    main()