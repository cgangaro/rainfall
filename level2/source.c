#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

void p(void)
{
    uintptr_t unaff_retaddr;
	char buffer[76];

	fflush(stdout);
	gets(buffer);
	if ((unaff_retaddr & 0xb0000000) == 0xb0000000)
	{
		printf("(%p)\n", (void *)unaff_retaddr);
		exit(1);
	}
	puts(buffer);
    strdup(buffer);
}

int		main(void)
{
	p();
	return (0);
}
