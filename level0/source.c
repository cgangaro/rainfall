#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int ac, char **av)
{
	int iVar1;
	char *execv_args[2];
	gid_t gid;
	uid_t uid;
	
	iVar1 = atoi(av[1]);
    if (iVar1 == 423) {
        execv_args[0] = strdup("/bin/sh");
        execv_args[1] = NULL;
        gid = getegid();
		uid = geteuid();
        setresgid(gid, gid, gid);
		setresuid(uid, uid, uid);
        execv("/bin/sh", execv_args);
    }
    else {
        fwrite("No !\n", 1, 5,stderr);
    }
	return (0);
}
