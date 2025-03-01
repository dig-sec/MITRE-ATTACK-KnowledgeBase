# Makefile for MITRE ATT&CK KnowledgeBase Script

# Variables
PYTHON = python3
PIP = pip
VENV = .venv
ACTIVATE = . $(VENV)/bin/activate
SCRIPT = main.py
DATA_DIR = data
ATOMICS_DIR = $(DATA_DIR)/atomics

# Default target
all: run

# Create a virtual environment
venv:
	$(PYTHON) -m venv $(VENV)
	@echo "Virtual environment created at $(VENV)"

# Install dependencies
install: venv
	$(ACTIVATE) && $(PIP) install -r requirements.txt
	@echo "Dependencies installed"

# Fetch data files
fetch_data: install
	$(ACTIVATE) && $(PYTHON) fetch_data.py
	@echo "Data files fetched"

# Download the atomics folder
atomics: $(ATOMICS_DIR)

$(ATOMICS_DIR):
	@echo "Downloading Atomic Red Team atomics..."
	mkdir -p $(DATA_DIR)
	cd $(DATA_DIR) && curl -LO https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip
	cd $(DATA_DIR) && unzip master.zip
	mv $(DATA_DIR)/atomic-red-team-master/atomics $(DATA_DIR)/
	rm -rf $(DATA_DIR)/master.zip $(DATA_DIR)/atomic-red-team-master
	@echo "Atomics downloaded to $(ATOMICS_DIR)"

# Run the script
run: fetch_data atomics
	$(ACTIVATE) && $(PYTHON) $(SCRIPT)

# Clean up generated files and virtual environment
clean:
	rm -rf MITRE_ATT&CK_Analysis/
	rm -rf $(VENV)/
	rm -rf $(ATOMICS_DIR)/
	@echo "Cleaned up generated files and virtual environment"

# Set up the environment and run the script
setup: run

# Help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  venv        Create a virtual environment"
	@echo "  install     Install dependencies"
	@echo "  fetch_data  Fetch necessary data files"
	@echo "  atomics     Download the Atomic Red Team atomics folder"
	@echo "  run         Run the script"
	@echo "  clean       Remove generated files and virtual environment"
	@echo "  setup       Set up the environment and run the script"
	@echo "  help        Show this help message"

.PHONY: all venv install fetch_data atomics run clean setup help