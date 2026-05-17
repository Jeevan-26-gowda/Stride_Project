# Automated STRIDE-Based Threat Modeling and Risk Analysis Platform

AI-powered project for automatically analyzing cloud-native application architecture using STRIDE, DREAD, OWASP mapping, and mitigation recommendations.

## What It Does

- Accepts a JSON DFD-style architecture input.
- Detects components such as frontend, API, database, cache, object storage, CI/CD, payment provider, and admin systems.
- Applies STRIDE rules per component and data flow.
- Generates 30+ threats for realistic cloud-native systems.
- Calculates DREAD scores and severity.
- Maps findings to OWASP categories.
- Produces a Markdown report that can be converted to PDF.

## UI Screens

1. Architecture Input: JSON editor for components, data flows, protocols, and trust boundaries.
2. AI Enhancement Panel: explains the NLP-style component detection and prioritization layer.
3. Risk Dashboard: total threats, critical count, component count, and data-flow count.
4. Heatmap: ranks components by maximum DREAD score.
5. STRIDE Distribution: counts threats by Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
6. Threat Register: table with component, threat, STRIDE type, DREAD score, severity, OWASP mapping, and mitigation.
7. Report Export: downloads a professional Markdown threat-model report.

## Code Structure

```text
.
├── api/
│   ├── Dockerfile
│   ├── package.json
│   └── src/server.js
├── data/stride-threats.csv
├── frontend/
│   ├── Dockerfile
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       └── styles.css
└── docker-compose.yml
```

## Run Locally

```bash
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- API health: http://localhost:8080/health

## AI-Powered Angle

This version uses a deterministic AI-style threat engine: component keyword matching, STRIDE rule expansion, heuristic DREAD scoring, OWASP mapping, and mitigation ranking.
