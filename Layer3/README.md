# ThreatMind — Layer 3 (Threat Investigation Agent)

Layer 3 contains Agent 2, the **Threat Investigation Agent**.

## Responsibilities
This layer is responsible for taking suspicious alerts/events from Layer 2 and turning them into fully investigated, structured incidents.

The pipeline performs:
1. **Event Correlation**: Grouping related events by entities (user, IP, host) and time.
2. **Entity Extraction**: Building a relationship graph of involved entities.
3. **Timeline Reconstruction**: Creating chronological timelines and identifying attack phases.
4. **MITRE ATT&CK Mapping**: Mapping observed behaviors to known adversarial techniques.
5. **Threat Intelligence Enrichment**: Checking indicators (IPs, hashes, etc.) against reputation sources.
6. **Dynamic Risk Scoring**: Calculating an explainable 0-100 risk score based on severity, correlation, and context.

## Output
The result is an `InvestigatedIncident` JSON object, which is consumed by Layer 4 (Agent 3 - Response, Agent 4 - Reporting) and the SOC Dashboard.

## Setup & Running

This project uses Python 3.11+.

1. **Activate the virtual environment**:
   ```bash
   # Windows
   .venv\Scripts\activate
   # Linux/Mac
   source .venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tests**:
   ```bash
   pytest tests/ -v
   ```

4. **Run the demonstration entry point**:
   ```bash
   python main.py
   ```
   *Note: Since Layer 2 is not yet implemented, `main.py` uses a mock adapter to load sample data from `data/`.*

## Roadmap
- **Phase 1 (Current)**: Deterministic investigation engine (rule-based correlation, mapping, and scoring).
- **Phase 2**: Development of discrete investigation tools (e.g., `search_events`, `check_ip`).
- **Phase 3**: Introduction of LLM reasoning to dynamically decide on investigation steps.
- **Phase 4**: Full agentic orchestration (tool calling and planning).
