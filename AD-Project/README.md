# Active Directory Project Home Lab

## Objective

The AD project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to create a domain in active directory, ingest and analyze logs within a Security Information and Event Management (SIEM), and generate test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, offensive stratagies, and defensive strategies.

### Skills Learned

- Set up an Active Directory home lab to understand how a domain environment functions.
- Learn to ingest events to Splunk by collecting and forwarding logs/events.
- Generate telemetry related to real-workd attacks.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Active Directory to configure a domain environment.
- Splunk for log ingestion and analysis.
- Kali Linux for penetration tesing.
- Atomic Red Team for simulating attacks and creating telemetry.

## Steps
1. Set up 4 virtual machines. Windows Server 2022 (AD Domain Controller), Windows 10 (Target-PC), Kali Linux (Attacking Machine), Ubuntu Server (Splunk).

2. <p>Created a <a href="https://imgur.com/a/HfG2QA9" style="color: blue; text-decoration: underline;">logical diagram</a> showing how the VMs were connected.</p>

3. Installed & configured Sysmon & Splunk on Target-PC and Windows 2022 server to collect telemetry to forward to Splunk server.
   
4. Installed & configured Windows Server with AD and promoted it to a domain controller, also configured Target-PC to join the domain.
   
5. Used Kali Linux to perform a brute-force attack using Crowbar on Target-PC. Viewed the telemetry via Splunk. Installed & deployed Atomic Red Team to generate telemetry in Powershell.
