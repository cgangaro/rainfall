# Rainfall

Rainfall is a virtual machine that contains several binaries with vulnerabilities. The goal is to exploit these vulnerabilities to gain access to the next level.

## Setup

Rainfall is a virtual machine, in the form of a ISO file.
You can create a virtual machine with the ISO file using a virtualization software like VirtualBox or VMware.

### VirtualBox

### Creating a Virtual Machine
1. Download and install [VirtualBox](https://www.virtualbox.org/wiki/Downloads).
2. Create a new virtual machine.
3. Choose the type and version of the virtual machine. For Rainfall, choose Linux and Debian (64-bit).
4. Allocate memory to the virtual machine. 2GB should be enough.
5. Create a virtual hard disk. 6GB should be enough.
Now, you have created a virtual machine.

### Configuring the Network for SSH Access attached to NAT
If you want to use SSH to connect to the virtual machine, you need to configure the network settings. You can attach the network adapter to NAT and use port forwarding to connect to the virtual machine.
1. Go to the settings of the virtual machine.
2. Go to the Network tab.
3. Change the attached to option to NAT.
4. Go to the Advanced tab.
5. Go to the Port Forwarding section.
6. Add a new rule with the following settings:
   - Name: [Whatever you want]
   - Protocol: TCP
   - Host IP: [Leave blank]
    - Host Port: [Whatever port you want to use. ex: 2222, 4444]
    - Guest IP: [Leave blank]
    - Guest Port: [Whatever port you want to use. ex: 4242]
7. Click OK to save the settings.
You can also use the Bridged Adapter option to connect the virtual machine to the network.

### Installing Rainfall
1. Download the Rainfall ISO file.
2. Start the virtual machine.
3. At the boot screen, select the option to boot from the ISO file.

## Tools

### Ghidra
**Ghidra** is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. It helps analyze malicious code and malware like viruses, and can give cybersecurity professionals a better understanding of potential vulnerabilities in their networks and systems.

For our purposes, Ghidra will be used to reverse engineer the binaries provided in the Rainfall project.
For installation instructions, visit the [Ghidra GitHub page](https://github.com/NationalSecurityAgency/ghidra/releases).

### Wiremask

**Wiremask** is a tool that can be used to generate a pattern to find the offset of a buffer overflow. You generate a pattern, send it to the program, and then find the offset of the return address by searching for the pattern in the memory dump.
You can use [Wiremask online](https://wiremask.eu/tools/buffer-overflow-pattern-generator/).
For exemple in a program which takes a argument, copy it in a buffer and you want overflow the buffer to overwrite the `eip`:
You can generate a pattern, send it to the program, and check the `eip` value.
```bash
user@RainFall:~$ gdb program
(gdb) run [PATTERN]
(gdb) info register eip
eip            0x41346341	0x41346341
```
The `eip` value is `0x41346341`. if the buffer has overflowed `eip`, you can find this value in the pattern to find the offset. You can indicate this value to `Wiremask` to find the offset.

## Tips

To get the binary files from the VM to your host machine, you can use `scp`.
```bash
scp -P [PORT] levelX@[IP]:~/levelX ~/[YOUR_PATH]/levelX
```

## Vulnerabilities found in Rainfall

### gets()
```c
char *gets(char *s);
```
`gets()` reads a line from `stdin` into the buffer pointed to by `s` until either a terminating newline or EOF is found.
It is vulnerable to buffer overflow attacks because it does not perform size checking on the buffer.
If the line is longer than the buffer, it will overwrite the memory following the buffer.

