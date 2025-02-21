# Makefile for MITRE ATT&CK KnowledgeBase Script

# Variables
PYTHON = python3
PIP = pip
VENV = .venv
ACTIVATE = . $(VENV)/bin/activate
SCRIPT = main.py  # Replace with your script's filename

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

# Run the script
run: install
	$(ACTIVATE) && $(PYTHON) $(SCRIPT)

# Clean up generated files and virtual environment
clean:
	rm -rf MITRE_ATT&CK_KnowledgeBase/
	rm -rf $(VENV)/
	@echo "Cleaned up generated files and virtual environment"

# Set up the environment and run the script
setup: install run

# Help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  venv      Create a virtual environment"
	@echo "  install   Install dependencies"
	@echo "  run       Run the script"
	@echo "  clean     Remove generated files and virtual environment"
	@echo "  setup     Install dependencies and run the script"
	@echo "  help      Show this help message"

.PHONY: all venv install run clean setup help