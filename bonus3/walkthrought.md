# bonus3 Exploit

## Steps

### 1. Understand the Vulnerability

The `bonus3` binary reads data from a `.pass` file into a buffer and then allows the user to manipulate this buffer by inserting a null byte (`\0`) at an index specified by the first argument converted via `atoi`. If the manipulated buffer matches the first argument, the program executes a shell.

### 2. Analyze the Source Code

Key operations in the `main` function are:
- Read two segments from the `.pass` file into a single buffer.
- Use `atoi` to convert the first argument to an integer.
- Place a null byte at the computed index in the buffer.
- If the beginning of the buffer matches the first argument, execute a shell.

### 3. Determine the Exploit Strategy

The goal is to make the comparison `strcmp(buffer, argv[1]) == 0` true by manipulating the buffer. By passing an empty string (`""`) as `argv[1]`, `atoi` will return `0`, and the program will insert a `\0` at the start of the buffer, effectively making the buffer empty before the comparison.

### 4. Exploit Execution

Run the binary with an empty string as the first argument:
```sh
./bonus3 ""
```
This command manipulates the buffer such that the first character becomes `\0`, leading `strcmp` to believe both the buffer and `argv[1]` are empty strings, thus returning `0` and executing the shell.

### 5. Verify the Exploit

If successful, the command should trigger a shell:
```sh
$ whoami
bonus3
$ cat /home/user/end/.pass
```
Retrieve the flag or the password from the output.