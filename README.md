# MITRE ATT&CK KnowledgeBase Processing

## Overview
This project automates the processing, enrichment, and summarization of MITRE ATT&CK techniques. It downloads the latest attack rule mappings, processes MITRE ATT&CK data, and generates structured summaries in Markdown following the Alerting & Detection Strategy (ADS) framework.

## Features
- **Fetch Data**: Downloads the latest MITRE ATT&CK CSV and attack rule map.
- **Enrich Data**: Integrates external data sources like CyCAT, Sigma rules, and Atomic Red Team tests.
- **Generate Summaries**: Uses an Ollama-powered language model to create ADS-style Markdown reports.
- **Automation**: Fully automates fetching, processing, and summarization.

## Project Structure
```
.
├── data/                     # Stores raw MITRE ATT&CK CSV and attack rule map
├── MITRE_ATT&CK_Analysis/    # Enriched JSON files
├── MITRE_ATT&CK_Summaries/   # Markdown summaries
├── fetch_data.py             # Fetches MITRE ATT&CK data
├── create_mitre_objects.py   # Processes and enriches MITRE ATT&CK techniques
├── ollama_summarizer.py      # Generates ADS-style summaries
├── Makefile                  # Automates setup and execution
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

## Installation
### Prerequisites
- Python 3.8+
- Virtual environment support
- [Ollama](https://ollama.com) installed for LLM-powered summarization

### Setup
```sh
make setup
```
This command will:
1. Create a virtual environment.
2. Install required dependencies.
3. Fetch the latest MITRE ATT&CK data.
4. Download Atomic Red Team atomics.
5. Process and enrich techniques.
6. Generate Markdown summaries.

## Usage
### Run the Pipeline
```sh
make run
```
This will fetch data, process it, and generate summaries.

### Clean Up
```sh
make clean
```
Removes generated files and resets the environment.

## Outputs
- **Processed Techniques**: Stored in `MITRE_ATT&CK_Analysis/`
- **Summarized Reports**: Saved in `MITRE_ATT&CK_Summaries/`

## Contribution
Feel free to submit issues or pull requests to improve the project!

## License
This project is licensed under the MIT License.

