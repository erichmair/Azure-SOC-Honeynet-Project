# Azure Honeynet + SOC (w/ Real-World Cyber Attacks)

[ FULL pic ]

## Introduction and Purpose

In this project, I constructed a small-scale honeynet and Security Operations Center (SOC) within Azure. The project aimed to compare metrics 'Before' and 'After' hardening an insecure lab environment. To obtain these metrics, log sources from various resources were ingested into my log repository (Log Analytics Workspace). These log sources were then utilized by my SIEM (Microsoft Sentinel) to build attack maps, trigger alerts, and create incidents. Microsoft Sentinel measured the metrics of the insecure environment over a 24-hour period. Following this phase, security controls were implemented to harden this virtual lab environment. The metrics analyzed were:

* SecurityEvent (Windows event logs)
* Syslog (Linux event logs)
* SecurityAlert (Log Analytics alerts triggered)
* SecurityIncident (incidents created by Sentinel)
* AzureNetworkAnalytics_CL (malicious flows allowed into the honeynet)

After the implementation of security controls, another 24-hour metric measurement phase was conducted, and the results obtained from these endeavors are presented below. The comparative analysis of metrics before and after the hardening process showcased a significant reduction in security incidents and a notable enhancement in its overall security posture. 

### Technologies, Azure Components, and Regulations Employed

* Azure Virtual Network (VNet)
* Azure Network Security Group (NSG)
* Azure Active Directory (renamed to Entra ID)
* Virtual Machines → 2 Windows, 1 Linux
* Microsoft SQL Server
* SQL Server Management Studio (SSMS)
* Log Analytics Workspace → with Kusto Query Language (KQL) queries
* Azure Key Vault → for secure secrets management
* Azure Storage Account → for data storage
* Microsoft Sentinel → Security Information and Event Management (SIEM)
* Microsoft Defender for the Cloud → protection of cloud resources
* Windows Remote Desktop → for remote access
* Command Line Interface (CLI) → for system management
* PowerShell → for automation and configuration management
* [NIST SP 800-53 r5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) → for security controls
* [NIST SP 800-61 r2](https://www.nist.gov/privacy-framework/nist-sp-800-61) → for incident handling guidance

<br />

## Architecture ‘Before’ Hardening the Environment

[ 'Before' pic ]

To gather metrics for the insecure environment, all resources were initially deployed with their endpoints exposed to the public internet to encourage malicious traffic. Additionally, I disabled the built-in VM firewalls, and configured the VMs’ Network Security Groups (NSGs) as open, allowing unrestricted traffic. Following the configuration of log collection and the establishment of security metrics, I conducted a 24-hour observation of the ‘Before’ environment.

### Metrics 'Before' Hardening

The following table shows the 24-hour metrics generated before hardening the environment:
11/20/2023, 12:05:40 PM → 11/21/2023, 12:05:40 PM

| Metric                                          | Count
| ----------------------------------------------- | -----
| **SecurityEvents** (Windows VMs):                    | 22,540
| **Syslog** (Linux VM):                               | 998
| **SecurityAlert** (Microsoft Defender for Cloud):    | 7
| **SecurityIncident** (Sentinel Incidents):           | 152
| **NSG Inbound Malicious Flows Allowed**:             | 2,385

### Attack Maps 'Before' Hardening

#### NSG Allowed Malicious Inbound Flows

[ pic ]

#### Linux SSH Authentication Failures

[ pic ]

#### Windows RDP/SMB Authentication Failures

[ pic ] 

#### MS SQL Server Authentication Failures

[ pic ] 

<br />

## Hardening the Environment

Now that I've gathered 'Before' metrics for my insecure lab environment, I proceeded to take steps to enhance its security posture. These hardening tactics included:
* Network Security Groups (NSGs): Strengthened by blocking all inbound and outbound traffic, except for designated public IP addresses needed access to the VMs. This ensured that only authorized traffic from trusted sources could access the VMs.
* Built-in Firewalls: Azure's built-in firewalls were configured on the VMs to restrict unauthorized access and protect resources from malicious connections. This included fine-tuning firewall rules based on each VM's service and responsibilities, mitigating the attack surface accessible to bad actors
* Private Endpoints: To boost the security of Azure Key Vault and Azure Storage, public endpoints were replaced with private endpoints. This ensured that these sensitive resources were limited to the virtual network, not the public internet.
* Subnetting: To further enhance security, a subnet was created for Azure Key Vault and Azure Storage, separating traffic and providing an additional layer of protection for those endpoints.

Following these measures, I proceeded to conduct another 24-hour observation for this 'After' environment.

<br />

## Architecture ‘After’ Hardening the Environment

[ 'After' pic ]

### Metrics ‘After’ Hardening

The following table shows the 24-hour metrics generated after hardening the environment:
11/25/2023, 10:41:17 AM → 11/26/2023, 10:41:17 AM

| Metric                                          | Count 
| ----------------------------------------------- | -----
| **SecurityEvents** (Windows VMs):                    | 9,061
| **Syslog** (Linux VM):                               | 1
| **SecurityAlert** (Microsoft Defender for Cloud):    | 0
| **SecurityIncident** (Sentinel Incidents):           | 0
| **NSG Inbound Malicious Flows Allowed**:             | 0

### Attack Maps ‘After’ Hardening

> **NOTE**: The following maps did not yield any results, indicating the absence of malicious activity instances in the 24 hours following the hardening.

#### NSG Allowed Malicious Inbound Flows

[ pic ]

#### Linux SSH Authentication Failures

[ pic ]

#### Windows RDP/SMB Authentication Failures

[ pic ] 

#### MS SQL Server Authentication Failures

[ pic ] 

<br />

## Comparing the 'Before' and 'After' Metrics

| Metric                                               | Count ('Before') | Count ('After') | Change (%) |
| ---------------------------------------------------- | ----- | ---- | ---- |
| **SecurityEvents** (Windows VMs):                    | 22,540 | 9,061 | -59.80% |
| **Syslog** (Linux VM):                               | 998 | 1 | -99.90% | 
| **SecurityAlert** (Microsoft Defender for Cloud):    | 7 | 0 | -100.00% | 
| **SecurityIncident** (Sentinel Incidents):           | 152 | 0 | -100.00% | 
| **NSG Inbound Malicious Flows Allowed**:             | 2,385 | 0 | -100.00% |

<br />

## Conclusion

Microsoft Azure was used to establish a mini honeynet. Log Analytics workspace served as the log repository for housing various log sources. Microsoft Sentinel was employed to trigger alerts and generate incidents from these log sources. A set of metrics was utilized to evaluate the environment for 24 hours both before and after hardening. Analyzing the net change in the table above revealed a significant reduction in incidents and security events, demonstrating the effectiveness of the applied security controls.


![Cloud Honeynet / SOC](https://i.imgur.com/jFMrONH.png)
### Technologies, Regulations, and Azure Components Utilized:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 Windows, 1 Linux) 
- Log Analytics Workspace with KQL Queries
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel
- Microsoft Defender for the Cloud
- Windows Remote Desktop
- Command Line Interface
- PowerShell
- NIST SP 800-53 r4
- NIST SP 800-61 r2

<br />

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/x6UdJrr.png)

Initially, all resources were deployed with high exposure for the "BEFORE" metrics. The VMs were configured with their NSGs and built-in firewalls set to allow all traffic, and all other resources were also deployed with public endpoints that were visible to the internet. Consequently, Private Endpoints were not utilized.

<br />

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/l91mgkr.png)

To improve the "AFTER" metrics, NSGs were made more secure by prohibiting ALL traffic except for my admin workstation, while all other resources were safeguarded by their built-in firewalls in addition to Private Endpoints.

<br />

## Attack Maps BEFORE Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/hP91wFgl.jpg)

<br />

![Linux Syslog Auth Failures](https://i.imgur.com/Lwbtvrfl.jpg)

<br />

![Windows RDP/SMB Auth Failures](https://i.imgur.com/F7XxAhql.jpg)

<br />

![MSSQL Auth Failures](https://i.imgur.com/fmAeMdfl.jpg)

<br />

## Metrics Before Hardening / Security Controls

Measured metrics in the insecure environment for 24 hours:
Start Time 2023-04-09 11:30 AM EST
Stop Time 2023-04-10 11:30 AM EST

| Metric                                          | Count
| ----------------------------------------------- | -----
| SecurityEvents (Windows VMs)                    | 34,063
| Syslog (Linux VM)                               | 7783
| SecurityAlert (Microsoft Defender for Cloud)    | 12
| SecurityIncident (Sentinel Incidents)           | 295
| NSG Inbound Malicious Flows Allowed             | 624

<br />

## Hardening Steps

The initial 24-hour study revealed that the lab was vulnerable to multiple threats due to its visibility on the public internet. To address these findings, I activated NIST SP 800-53 r4 within the compliance section of Microsoft Defender and focused on fulfilling the compliance standards associated with SC.7.*. Additional assessments for SC-7 - Boundary Protection.

![Hardening](https://i.imgur.com/Ac5PNYQl.jpg)
       
<br />

## Attack Maps AFTER Hardening / Security Controls

``` There were no results to display for the 24-hour repeat map queries following the hardening of the assets. ```

<br />

## Metrics After Hardening / Security Controls

Measured metrics in the secure environment for another 24 hours after applying security controls:
Start Time 2023-04-10 11:30 AM EST
Stop Time	2023-04-11 11:30 AM EST

| Metric                                          | Count
| ----------------------------------------------- | -----
| SecurityEvents (Windows VMs)                    | 11,679
| Syslog (Linux VM)                               | 33
| SecurityAlert (Microsoft Defender for Cloud)    | 0
| SecurityIncident (Sentinel Incidents)           | 10
| NSG Inbound Malicious Flows Allowed             | 30

<br />

## Overall Improvement

| Metric                                          | Count
| ----------------------------------------------- | -----
| SecurityEvents (Windows VMs)                    | -65.71%
| Syslog (Linux VM)                               | -99.58%
| SecurityAlert (Microsoft Defender for Cloud)    | -100%
| SecurityIncident (Sentinel Incidents)           | -96.61%
| NSG Inbound Malicious Flows Allowed             | -95.19%

![48 Hour Improvement](https://i.imgur.com/eUzTyCDl.png)

<br />

## Simulated Attacks

I also took the opportunity to simulate specific attacks via PowerShell scripts or by manually triggering events. The results were observed in Log Analytics Workspace and Sentinel Incident Creation.  

- Linux Brute Force Attempt 
- AAD Brute Force Success 
- Windows Brute Force Success
- Malware Detection (EICAR Test File) 
- Privilege Escalation  

![Attacker](https://i.imgur.com/CpoVQw7l.png)

<br />

## Utilizing NIST 800.61r2 Computer Incident Handling Guide

For each simulated attack I then practiced incident responses following NIST SP 800-61 r2.

![NIST 800.61](https://i.imgur.com/6PTG7c0l.png)

Each organization will have policies related to an incident response that should be followed. This event is just a walkthrough for possible actions to take in the detection of malware on a workstation.  

#### Preparation

- The Azure lab was set up to ingest all of the logs into Log Analytics Workspace, Sentinel and Defender were configured, and alert rules were put in place.

#### Detection & Analysis

- Malware has been detected on a workstation with the potential to compromise the confidentiality, integrity, or availability of the system and data.
- Assigned alert to an owner, set the severity to "High", and the status to "Active"
- Identified the primary user account of the system and all systems affected.
- A full scan of the system was conducted using up-to-date antivirus software to identify the malware.
- Verified the authenticity of the alert as a "True Positive".
- Sent notifications to appropriate personnel as required by the organization's communication policies.

#### Containment, Eradication & Recovery

- The infected system and any additional systems infected by the malware were quarantined.
- If the malware was unable to be removed or the system sustained damage, the system would have been shut down and disconnected from the network.
- Depending on organizational policies the affected systems could be restored known clean state, such as a system image or a clean installation of the operating system and applications. Or an up-to-date anti-virus solution could be used to clean the systems. 

#### Post-Incident Activity

- In this simulated case, an employee had downloaded a game that contained malware. 
- All information was gathered and analyzed to determine the root cause, extent of damage, and effectiveness of the response. 
- Report disseminated to all stakeholders.
- Corrective actions are implemented to remediate the root cause.
- And, a lessons-learned review of the incident was conducted.

<br />

## Conclusion

In this project, I utilized Microsoft Azure to create a honeynet and ingest logs from various resources into a Log Analytics workspace.  Microsoft Sentinel was used to create attack maps, trigger alerts, and incidents.  I then gathered metrics over 48 hours to display the significance of properly configuring cloud assets with security in mind. By implementing one section of NIST SP 800-53 r4 I was able to drastically reduce the number of security events and incidents. 

Had this simulation been linked to an actual organization there would have been many more avenues of attack on the confidentiality, availability, and integrity of the organization's assets.

<br />

## Credits

This project was based on a course developed by Josh Madakor which can be found here: [leveld](https://www.leveldcareers.com/cyber-security-course)

Josh also produces a lot of great content over at YouTube: [Josh Madakor](https://www.youtube.com/@JoshMadakor)
