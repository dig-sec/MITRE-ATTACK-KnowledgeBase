#!/usr/bin/env python
import os
import json
import re
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List
from ollama import chat, ChatResponse

# Directories
INPUT_DIR = "MITRE_ATT&CK_Analysis"         # Folder containing MITRE ATT&CK JSON files
OUTPUT_DIR = "MITRE_ATT&CK_Summaries"         # Folder to store ADS-style Markdown summaries
OLLAMA_MODEL = "phi4"                         # Local Ollama model to use

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def sanitize_filename(name: str) -> str:
    """Sanitize a string for safe filenames."""
    return re.sub(r'[^a-zA-Z0-9_\- ]', '_', name)

@dataclass
class TechniqueData:
    """Container for extracted MITRE ATT&CK technique data."""
    id: str
    name: str
    description: str
    platforms: str = ""
    kill_chain_phases: str = ""
    data_sources: str = ""
    detection: str = ""
    url: str = ""
    sigma_rules: List[str] = field(default_factory=list)
    atomic_test_names: List[str] = field(default_factory=list)

class PromptTemplates:
    """Templates for generating ADS-style Markdown reports via the LLM."""
    TEMPLATES = {
        "technique_summary": """
Create a detailed **Markdown report** following Palantir's Alerting & Detection Strategy (ADS) framework.

## **Goal**
Describe what this technique aims to detect. For example, *detect adversarial attempts to bypass security monitoring using containers*.

## **Categorization**
- **MITRE ATT&CK Mapping:** {id} - {name}
- **Tactic / Kill Chain Phases:** {kill_chain_phases}
- **Platforms:** {platforms}
- [MITRE ATT&CK Reference]({url})

## **Strategy Abstract**
Summarize the detection strategy. Describe which data sources are used and what patterns are analyzed.

## **Technical Context**
Provide background on the technique, including how adversaries execute it in the real world.
Include any adversary emulation details such as sample commands or test scenarios.

## **Blind Spots and Assumptions**
List known limitations, assumptions, or gaps in the detection.

## **False Positives**
Identify potential benign activities that might trigger false alerts.

## **Priority**
Assess the severity (Low/Medium/High) with justification.

## **Validation (Adversary Emulation)**
Step-by-step instructions to emulate this technique in a test environment:
{validation_steps}

## **Response**
Guidelines for analysts when the alert fires.

## **Additional Resources**
Additional references and context:
{additional_resources}

Ensure the final output is clean, without extraneous markdown code fences or added text.
"""
    }

    @classmethod
    def get_template(cls, key: str) -> str:
        return cls.TEMPLATES.get(key, "")

def setup_logging() -> logging.Logger:
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler("ollama_summarizer.log"), logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

class OllamaSummarizer:
    """Handles LLM-assisted summarization via Ollama."""
    def __init__(self, logger: logging.Logger, max_retries: int = 3):
        self.logger = logger
        self.max_retries = max_retries

    def summarize_technique(self, technique: TechniqueData) -> Dict[str, str]:
        """Generate an ADS-style Markdown summary using the local Ollama model."""
        bullet_tests = "\n".join(f"- {test}" for test in technique.atomic_test_names) if technique.atomic_test_names else "- None available"
        bullet_sigma = "\n".join(f"- {rule}" for rule in technique.sigma_rules) if technique.sigma_rules else "- None available"

        prompt_data = {
            "id": technique.id,
            "name": technique.name,
            "description": technique.description,
            "platforms": technique.platforms,
            "kill_chain_phases": technique.kill_chain_phases,
            "detection": technique.detection,
            "url": technique.url,
            "validation_steps": bullet_tests,
            "additional_resources": bullet_sigma
        }

        prompt = PromptTemplates.get_template("technique_summary").format(**prompt_data)

        for attempt in range(self.max_retries):
            try:
                response: ChatResponse = chat(
                    model=OLLAMA_MODEL,
                    messages=[{'role': 'user', 'content': prompt}]
                )
                return {"summary": response.message.content.strip()}
            except Exception as e:
                self.logger.error(f"Ollama summary error (attempt {attempt+1}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

        return {"error": "Failed to generate summary"}

def parse_mitre_json(data: dict) -> TechniqueData:
    """Extract MITRE ATT&CK technique fields into a structured format."""
    technique = TechniqueData(
        id=data.get("id", ""),
        name=data.get("name", ""),
        description=data.get("description", ""),
        platforms=data.get("platforms", ""),
        kill_chain_phases=data.get("kill_chain_phases", ""),
        data_sources=data.get("data_sources", ""),
        detection=data.get("detection", ""),
        url=data.get("url", "")
    )

    # Extract Sigma rules from enrichments
    enrichments = data.get("enrichments", {})
    attack_rule_map = enrichments.get("attack_rule_map", [])
    technique.sigma_rules = [
        sr.get("rule_name")
        for rule_map in attack_rule_map
        for sr in rule_map.get("sigma_rules", [])
        if sr.get("rule_name")
    ]

    # Extract Atomic Test names from enrichments
    atomics = enrichments.get("atomics", [])
    technique.atomic_test_names = [
        t.get("name")
        for atomic_block in atomics
        for t in atomic_block.get("atomic_tests", [])
        if t.get("name")
    ]

    return technique

def main():
    """Main processing loop: Read JSON files, generate ADS Markdown reports, and save output files."""
    logger = setup_logging()
    summarizer = OllamaSummarizer(logger)

    for root, _, files in os.walk(INPUT_DIR):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    technique = parse_mitre_json(data)
                    summary_result = summarizer.summarize_technique(technique)

                    # Create output filename as "Txxxx TechniqueName.md"
                    base_filename = f"{technique.id} {technique.name}"
                    safe_filename = sanitize_filename(base_filename)
                    md_filename = f"{safe_filename}.md"
                    readme_path = os.path.join(OUTPUT_DIR, md_filename)

                    with open(readme_path, "w", encoding="utf-8") as md_file:
                        md_file.write(summary_result.get("summary", ""))

                    logger.info(f"Saved summary for {technique.id} as {md_filename}")

                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {e}")

if __name__ == "__main__":
    main()
