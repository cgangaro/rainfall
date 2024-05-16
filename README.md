# Rainfall

[project resume]

## Tools

**Ghidra** is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. It helps analyze malicious code and malware like viruses, and can give cybersecurity professionals a better understanding of potential vulnerabilities in their networks and systems.

For our purposes, Ghidra will be used to reverse engineer the binaries provided in the Rainfall project.
For installation instructions, visit the [Ghidra GitHub page](https://github.com/NationalSecurityAgency/ghidra/releases).

## Tips

To get the binary files from the VM to your host machine, you can use `scp`.
```bash
scp -P [PORT] levelX@[IP]:~/levelX ~/[YOUR_PATH]/levelX
```