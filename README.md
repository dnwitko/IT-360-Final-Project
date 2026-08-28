# Project Proposal

## Overview 
**Project name:** Log Analysis And Summary Tool (L.A.A.S.T)  
**Description:** A post-intrusion detection tool that analyzes log files of different formats (.txt, .evtx, etc.) and generates a comprehensive summary of the data found.  

**Objectives:**  
- Analyze log files
- Ability to parse multiple different file formats
- Relatively fast speeds
- Summary generated is accurate to the scenario 

**Success criteria:**  
Provide a file path to a folder or a drive and analyze most or all log files associated, then generate an accurate summary of the data.  

**Start Date:** August 27th, 2026  
**End Date:** December 5th, 2026  
  
## Stakeholders 
**Sponsor designation:** Santander Bank will commission Mandiant for an internal audit, who will license our tool [2][3].

### **Stakeholder list:**  

**Santander Bank**[3]  
- **CISO (Chief Info Security Officer):** Allocates funding and oversees the project.
- **SOC Lead:** Coordinates the teams and provides expertise on subject matter.
- **Internal Data Owners:** Provides sample logs for analysis and testing.

**Mandiant**[2]  
- **Incident Response Engagement Director:** Oversees project delivery, budget management, scope adherence, and final presentation.  
- **Security Analyst:** Deploys our log analysis tool. Essentially the main user of the product.  

**Development Team**  
- **Developers:** Ensures the tool works correctly and acts as a point of contact for Mandiant. Maintains transparency with other stakeholders.

## Scope Management 
**In-scope items:**  
- File directory traversal
- Parsing Windows Event Logs (.evtx) and text (.txt) logs
- LLM API integration for narrative generation
- Identifying and flagging un-analyzable/suspicious files for manual review
- Generating a final text/HTML report

**Out-of-scope items:** [1]  
- Live memory analysis/RAM analysis
- Active network monitoring
- Decrypting encrypted files

### **Project assumptions and constraints:**   
**Assumptions:**  
- Logs follow a standard format
- The LLM Model is available when needed
- Drain3 and NetworkX work as intended  

**Constraints:**  
- Time constraints
- Encrypted file formats
- Lack of log context (nothing to piece clues together from)
- Sensitive documents exposing personally identifiable information (PII)

## Timeline 
1. **Project Proposal/Plan** - Submitted by August 27, 2026.
2. **Log Parsing (Drain3)** - Functional by middle of September.
3. **Flagging/Reporting (NetworkX)** - Functional by middle of October.
4. **AI/LLM Summary** - Functional by the first week of November.
5. **Testing** - Fully completed by last week of November.
6. **Submit Project** - Submitted during first week of December.

 ## Risk Management 
- LLM Hallucinations/Inaccurate Analysis
  - Impact: Medium
  - Probability: Low
  - Mitigation: Exploring various models to find the best qualities.
- Malformed or Corrupted logs [1]
  - Impact: Medium
  - Probability: Low
  - Mitigation: Flagging files for manual review, compiled into a comprehensive list.
- Encrypted Files
  - Impact: High
  - Probability: Medium
  - Mitigation: Decrypt first, analyze later; Flag files for manual review.

 ## Resources 
**Budget Allocation:** [1]    
We will need a budget of $20.00 - $50.00 for API credits, but if the LLM is good enough to run locally, we will need a $0.00 budget to complete this project. 

**Required Tools and Technology:**  
- Python 3.0
- python-evtx library
- LLM API keys
- Sample attack logs [1]  

**Project Dependencies:** [1]  
- **drain3 (version 0.9.11):** Dynamic Log Template Mining for parsing different types of log files.   
- **networkx (version 3.1):** Maps data into graphs for creating a timeline of events, identifying key variables, etc.  
- **evtx (version 0.7.4):** Python Library for parsing Windows Event Logs.  
- **colorama (version 0.4.6, optional):** Makes terminal output prettier.  

## Communication 
**Meeting Cadence and Reporting Frequency:**  
We will plan to meet and report progress at least once per week with each other.  

**Communication Channels:**  
iMessage, Microsoft Teams, Microsoft Outlook  

## Action Items 
- Meeting with Stakeholders regularly to hear their comments on requirements.
- Environment setup and dependency installation.
- Gather common forensic log file paths.
- Configure Drain3 and python-evtx.
- Implement NetworkX.
- LLM integration and report generation testing.

## References
[1] - Google Gemini  
[2] - Mandiant: https://www.zdnet.com/article/fireeyes-mandiant-debuts-new-saas-threat-intelligence-suite/  
[3] - Santander Bank: https://therecord.media/santander-employees-bank-breach-affected
