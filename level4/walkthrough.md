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