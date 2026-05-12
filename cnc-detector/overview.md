# C&C Server Detection System - Technical Overview

## 1. Project Objective
The C&C (Command & Control) Server Detection System is an advanced, AI-driven cybersecurity research tool designed to monitor live network traffic and detect malicious communications initiated by malware/botnets. The system employs a multi-layered approach, combining heuristic rules with state-of-the-art Machine Learning models to identify stealthy C&C behaviors such as beaconing and DGA (Domain Generation Algorithm) usage.

## 2. System Architecture
The application is built on a modular architecture to ensure scalability and real-time processing capability:

- **Packet Sniffer & Flow Extractor (`packet_sniffer.py`)**: Utilizes `scapy` to capture raw network packets in real-time. Packets are aggregated into "Flows" (based on 5-tuple: src_ip, src_port, dst_ip, dst_port, protocol). It computes complex time-series statistical features (e.g., Inter-Arrival Time (IAT), Active/Idle Means, Packet Length distributions).
- **Process Mapper (`process_mapper.py`)**: Employs `psutil` to correlate active network sockets with local operating system processes. This helps identify "Masquerading" techniques where malware injects into legitimate processes (e.g., `svchost.exe`, `explorer.exe`).
- **AI Modules**:
  - **Flow Analyzer (`flow_analyzer.py`)**: The behavioral analysis engine.
  - **DGA Detector (`dga_detector.py`)**: The lexical analysis engine for domains.
- **Threat Intelligence (`threat_intel.py`)**: A module designed to cross-reference target IP addresses and domains against known malicious indicators of compromise (IoC) databases.
- **Ensemble Risk Scorer (`risk_scorer.py`)**: Aggregates the predictions from the AI models, process mapping, and threat intel to calculate a normalized Final Risk Score (0-100). It outputs Alert Levels (SAFE, LOW, MEDIUM, HIGH, CRITICAL).
- **GUI Engine (`main.py`)**: A modern, asynchronous interface built with `CustomTkinter`. It features real-time data grids, dynamic plotting (`matplotlib`), log exports (`csv`), and multi-threading to prevent UI blocking during packet capture.

## 3. Machine Learning Algorithms

### A. XGBoost (Extreme Gradient Boosting) for Flow Analysis
- **Algorithm**: XGBoost (Tree-based ensemble method).
- **Purpose**: Classifies network flows as either Benign or C&C Beaconing.
- **Why XGBoost?**: It is highly efficient for tabular/statistical data, robust against overfitting, and can handle non-linear decision boundaries.
- **Key Features Engineered**:
  - `flow_duration`, `flow_bytes_per_sec`, `flow_packets_per_sec`.
  - `flow_iat_mean`, `active_mean`, `idle_mean`: Crucial for detecting "Beaconing" (periodic heartbeat signals sent by malware to the C&C server). C&C traffic typically exhibits high idle times with very short active bursts.
  - `syn_flag_count`, `ack_flag_count`: Identifies unusual TCP handshakes or scanning behaviors.

### B. Bi-LSTM (Bidirectional Long Short-Term Memory) for DGA Detection
- **Algorithm**: Deep Recurrent Neural Network (RNN) using Bidirectional LSTM.
- **Purpose**: Analyzes the lexical structure of domain names (character by character) to detect randomly generated domains used by malware to evade static IP blocking.
- **Architecture**:
  - **Embedding Layer**: Converts character sequences into dense vectors.
  - **Bi-LSTM Layer**: Reads the domain string both forwards and backwards to capture sequential dependencies and patterns (e.g., vowel-to-consonant ratios, entropy).
  - **Dense Layer**: Outputs a probability score indicating whether the domain is a DGA.

## 4. Datasets & Model Training
*(Note: As a research demo, the system is capable of generating simulated training data internally. However, in production, the models are designed to be trained on the following benchmark datasets)*

- **Network Flow Data (XGBoost)**:
  - **CTU-13 Dataset**: Contains labeled botnet, normal, and background traffic. Excellent for modeling real-world C&C beaconing.
  - **CICIDS2017 / CSE-CIC-IDS2018**: Contains modern attack profiles alongside benign traffic, providing robust timing and flow-level features.
- **DGA Domain Data (Bi-LSTM)**:
  - **Benign Class**: Alexa Top 1 Million / Cisco Umbrella Top 1M domains.
  - **Malicious Class**: Bambenek Consulting DGA feeds, OSINT DGA lists (covering families like Cryptolocker, Conficker, Zeus).

## 5. Execution Modes
- **Live Capture**: Uses WinPcap/Npcap to sniff actual host traffic.
- **Demo Scenarios (Mixed/Clean/Malicious)**: Simulates synthetic network flows to test system responsiveness and AI accuracy without requiring a live malware infection.
