#include <stdio.h>
#include <string.h>
#include <unistd.h>

void p(char *param_1,char *param_2)
{
    char *pcVar1;
    // char local_100c [4104];
    char buffer[40];
    
    puts(param_2);
    // read(0,local_100c,0x1000);
    // 0x1000 = 4096
    read(0, buffer, 4096);
    // pcVar1 = strchr(local_100c,10);
    // 10 = '\n'
    pcVar1 = strchr(buffer, '\n');
    *pcVar1 = '\0';
    strncpy(param_1, buffer, 20);
    return;
}

void pp(char *param_1)
{
    char buffer1[20];
    char buffer2[20];
    int len;
    // char cVar1;
    // uint uVar2;
    // char *pcVar3;
    // byte bVar4;

    // bVar4 = 0;
    // p(local_34,&DAT_080486a0);
    // p(local_20,&DAT_080486a0);
    // We cannot find the value of &DAT_080486a0 in the binary
    // But we can see that this string is the same for both calls
    // And in the p function, the second parameter is printed before the input
    // So we can assume that it's ' - ' according to the output
    p(buffer1, " - ");
    p(buffer2, " - ");
    strcpy(param_1,buffer1);
    // uVar2 = 0xffffffff;
    // pcVar3 = param_1;
    // do {
    //     if (uVar2 == 0) break;
    //     uVar2 = uVar2 - 1;
    //     cVar1 = *pcVar3;
    //     pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
    // } while (cVar1 != '\0');
    // Count the number of characters in the string
    // Same operation as level8
    // The principle is an a decrementation of uVar2 to count the number of characters
    // With an incrementation of pcVar3 pointer to go through the string
    // *(undefined2 *)(param_1 + (~uVar2 - 1)) = 0x20;
    // '~' is a NOT operator, so for our uint uVar2, it will be the opposite
    // So (~uVar2 - 1)) it's the length of the string
    // 0x20 is the space character
    // So the line above add a space at the end of the string
    len = strlen(param_1);
    param_1[len] = ' ';
    param_1[len + 1] = '\0';
    // This line above isn't in the decompliation
    // But it's necessary to reproduce the same output as the binary
    strcat(param_1,buffer2);
    return;
}

int main(void)
{
    char buffer[42];

    pp(buffer);
    puts(buffer);
    return (0);
}