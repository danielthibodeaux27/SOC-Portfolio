# SOC-Automation-Lab

## Objective

The primary objective is to develop practical skills in setting up a simulated SOC infrastructure, automating alert handling and incident response, simulating attacks, and performing investigations. In this project we will go from nothing at all to a full Wazuh instance with SOAR integration along with a fully functional case management system using TheHive. All VMs in this project were spun up on-premises.

### Skills Learned

- Learn how to draw a logical diagram connecting all VMs.
- Setup and configure Wazuh, TheHive, and Shuffle.
- Configure the servers and endpoints to talk to one another.
- Generate Telemetry on our endpoint to trigger an alert on Wazuh.
- Setup SOAR and integrated all of the tools used together.
- Learn how events are sent over to the SOAR and created in TheHive.


### Tools Used

- Vmware to set up VM instances
- Wazuh as SIEM & XDR
- TheHive for case management
- MimiKatz to generate telemetry
- Shuffle for SOAR capabilities

## Steps
All steps in detail can be found <a href="https://docs.google.com/document/d/10zMMvIM3Co88ea8d9Oz_KLhqIRQL8id-xAwQpetT1V8/edit?tab=t.0" style="color: blue; text-decoration: underline;">here</a>

1. Create a <a href="https://imgur.com/a/2UHeALS" style="color: blue; text-decoration: underline;">logical diagram</a> and map out how we want to build out our lab visually to understand how data flows.

2. Install VMs & Applications.

3. Configure our TheHive & Wazuh servers.

4. Configure Windows 11 machine to start sending our sysmon telemetry over to our Wazuh manager. Then create a custom detection rule looking for MimiKatz activity.

5. Combine all of our tools (including Shuffle) and create a working automation.
