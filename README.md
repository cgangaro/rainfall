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

### gets
```c
char *gets(char *s);
```
`gets()` reads a line from `stdin` into the buffer pointed to by `s` until either a terminating newline or EOF is found.
It is vulnerable to buffer overflow attacks because it does not perform size checking on the buffer.
If the line is longer than the buffer, it will overwrite the memory following the buffer.

### printf
```c
int printf(const char *format, ...);
```
`printf()` is a function that prints formatted output to the standard output stream.
It is vulnerable to format string attacks if the format string is not properly sanitized.
An attacker can use format specifiers to read or write arbitrary memory locations.

`printf()` use the stack to store the format string and the arguments.
`printf("%d %d", 1, 2);`, the format string `"%d %d"` is stored on the stack, followed by the arguments `1` and `2`.

When we call `printf("%x %x %x")`, the format string is `"%x %x %x"`, and the arguments are missing. `printf()` will read the arguments from the stack, and print the values at the addresses pointed to by the arguments. So it will print the values found on the stack.

`%n%` is a format specifier that writes the number of characters written by `printf()` to the corresponding argument.
```c
int count;
printf("Hello, world!%n\n", &count);
```
`count` will be set to `13`, the number of characters written by `printf()` with 'Hello, world!'.
So with %n, we can write to memory locations.

When `printf()` is called, maybe other functions are called before `printf()` finishes. So the stack is not always in the same state when `printf()` is called. We can use `%x` to print the values on the stack to find the address of the format string.
```c
printf("aaaa" + " %x" * 15)
```
Return:
```bash
aaaa b7ff26b0 bffff744 b7fd0ff4 0 0 bffff708 804848d bffff500 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825 78252078
```
`aaaa` is the string "aaaa", and `61616161` is the hexadecimal representation of the string "aaaa".
In the return, we can see different values on the stack. We can see that `61616161` is at the 12th position on the stack. So when we use our binary using printf, we can write to the 12th argument on the stack.

So if we use `printf("%12$x\n")`, it will print the 12th argument on the stack.
Let's imagine in our case the address of the variable that we want to change is `0x8049810` (`\x10\x98\x04\x08` in little-endian).
We can use 
`printf("\x10\x98\x04\x08")` to write to the address `0x8049810` to the 12th argument on the stack.

`%d` is used to print the decimal value of the argument.
`%200d` is used to print a decimal value with a width of 200 characters.

SO if we use `printf("\x10\x98\x04\x08" + "%200d%12$n")`:
- `"\x10\x98\x04\x08"` will write on the stack to the 12th argument.
- `"%n"` will write the number of characters written by `printf()` to the address pointed.
- `%12$n` will write the number of characters written by `printf()` to the address pointed by the 12th argument.
- `%200d%12$n` will write 200 characters to the address pointed by the 12th argument.
The value of the 12th argument is `0x8049810`, so it will write 200 characters + the previous number of characters, here 4. So it will write 204 characters to the address `0x8049810`.

With this, we can write any value to any address.