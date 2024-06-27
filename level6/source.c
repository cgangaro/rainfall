#include <stdio.h>   // puts
#include <stdlib.h>  // malloc & system
#include <string.h>  // strcpy

typedef void (*function_ptr)(void);

void m(void)
{
    puts("Nope");
    return;
}

void n(void)
{
    system("/bin/cat /home/user/level7/.pass");
    return;
}

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
