# Project summary

**Name:** VulnSight (Web-Vuln-Scanner)  
**Type:** Modular authorized web vulnerability scanner (CLI)  
**Group:** Group 3  
**License:** MIT  
**Language:** Python 3.10+

## Group 3 members

| Student name | Student ID |
|--------------|------------|
| Kenean Amare Eshet | CTC-4837-26 |
| Kenneti Hailu Dange | CTC-535-26 |
| Kidsit Ephrem | CTC-6744-26 |
| Alazar Elias Digafe | CTC-631-26 |
| Firaol Mustefa Gossa | CTC-4301-26 |

## Purpose

VulnSight demonstrates a complete, ethically constrained scanning pipeline suitable for academic evaluation: explicit authorization, reconnaissance, multi-class detection, and professional reporting.

## Deliverables

1. Integrated CLI (`vulnsight`) orchestrating all modules
2. Independent member modules with shared finding contracts
3. HTML, Markdown, PDF, and JSON assessment reports
4. Documentation for installation, usage, architecture, and demo
5. Automated tests (`pytest`)

## Typical demonstration flow

1. Install and run `vulnsight doctor`
2. Start an authorized local target website
3. `vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT`
4. `vulnsight scan --project myproject.json`
5. Present `reports/vulnsight_report.html` (and PDF/Markdown downloads)

## Out of scope

- Bundled deliberately vulnerable target application
- Unauthorized or external scanning without explicit operator consent
- Guaranteed complete coverage of all vulnerability classes
