Below is a comprehensive `README.md` file for your project. This file provides an overview of the project, instructions for setup, usage, and other relevant details.

---

# MITRE ATT&CK KnowledgeBase Project

This project fetches MITRE ATT&CK techniques, enriches them with additional data from the CyCAT API, and organizes the results into a structured directory based on tactics. The data is saved in JSON format for easy access and analysis.

---

## **Table of Contents**

1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
4. [Usage](#usage)
5. [Directory Structure](#directory-structure)
6. [Contributing](#contributing)
7. [License](#license)

---

## **Features**

- Fetches MITRE ATT&CK techniques using the MITRE ATT&CK API.
- Enriches techniques with additional data from the CyCAT API.
- Organizes results into a directory structure based on tactics.
- Saves each technique's data as a JSON file for easy access.

---

## **Prerequisites**

Before running the project, ensure you have the following installed:

- **Python 3.8+**
- **pip** (Python package manager)

---

## **Setup**

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/mitre-attack-knowledgebase.git
   cd mitre-attack-knowledgebase
   ```

2. **Set up the virtual environment and install dependencies**:
   ```bash
   make install
   ```

   This command will:
   - Create a virtual environment (`.venv`).
   - Install the required dependencies listed in `requirements.txt`.

---

## **Usage**

### **Run the Script**
To fetch MITRE ATT&CK techniques, enrich them with CyCAT data, and save the results, run:
```bash
make run
```

### **Clean Up**
To remove the generated data and virtual environment, run:
```bash
make clean
```

### **Other Commands**
- **Set up and run the script**:
  ```bash
  make setup
  ```

- **Display help**:
  ```bash
  make help
  ```

---

## **Directory Structure**

After running the script, the project directory will look like this:

```
mitre-attack-knowledgebase/
├── .venv/                          # Virtual environment
├── MITRE_ATT&CK_KnowledgeBase/     # Generated data (organized by tactics)
│   ├── Tactic_Name_1/
│   │   ├── T1234.json
│   │   ├── T5678.json
│   ├── Tactic_Name_2/
│   │   ├── T4321.json
│   │   ├── T8765.json
├── main.py                  # Main Python script
├── Makefile                        # Makefile for automation
├── requirements.txt                # List of dependencies
└── README.md                       # Project documentation
```

---

## **Contributing**

Contributions are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes and push to the branch.
4. Submit a pull request.

---

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## **Acknowledgments**

- [MITRE ATT&CK](https://attack.mitre.org/) for providing the techniques and tactics data.
- [CyCAT](https://cycat.org/) for enriching the techniques with additional information.

---
