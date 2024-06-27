#include <stdio.h>
#include <stdlib.h>

int	m = 0;

int	p(char *param_1)
{
	printf(param_1);
	return(0);
}

int	n(void)
{
	char	local_20c[512];

	fgets(local_20c, 512, stdin);
	p(local_20c);
	if (m == 16930116)
		system("/bin/cat /home/user/level5/.pass");
	return(0);
}

int	main(void)
{
	n();
	return(0);
}
