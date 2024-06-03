# Rainfall

[project resume]

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

