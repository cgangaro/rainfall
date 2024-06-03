#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int *auth = NULL;
char *service = NULL;

int main(void)
{
  char input[128];
  uint uVar4;
  char local_8b[2];
  // char bVar12;
  // char *pcVar2;
  // bool bVar7;
  // bool uVar8;
  // bool uVar11;
  // bool bVar10;
  // int iVar3;
  // u_int8_t *pbVar6;
  // char cVar1;
  // u_int8_t *pbVar5;
  // u_int8_t uVar9;
  char acStack_89 [125];
  
  do {
    printf("%p, %p\n", auth, service);
    if (fgets(input,0x80,stdin) == NULL) {
      return 0;
    }
    // pbVar5 = input;
    // pbVar6 = (u_int8_t *)"auth ";
    // do {
    //   bVar7 = *pbVar5 < *pbVar6;
    //   bVar10 = *pbVar5 == *pbVar6;
    //   pbVar5 = pbVar5 + bVar12 * -2 + 1;
    //   pbVar6 = pbVar6 + bVar12 * -2 + 1;
    // } while (bVar10);
    // uVar11 = (!bVar7 && !bVar10) == bVar7;
    // if (uVar11) {
    // This code above check one by one character if it is equal to "auth ".
    // We can simplify this by using strncmp function.
    if (strncmp(input, "auth ", 5) == 0) {

      // auth = (int *)malloc(4);
      // *auth = 0;
      // uVar4 = 0xffffffff;
      // pcVar2 = local_8b;
      // Here pcVar2 is a pointer to local_8b, but if we look the decompilation
      // in Ghidra, we can see that pcVar2 = EAX + 0x05.
      // Furthermore, the code below counts the length of the string.
      // So it's more likely that it's the user input.

      // do {
      //   if (uVar4 == 0) break;
      //   uVar4 = uVar4 - 1;
      //   cVar1 = *pcVar2;
      //   pcVar2 = pcVar2 + 1;
      // } while (cVar1 != '\0');
      // In this loop above, the pointer pcVar2 is incremented by 1.
      // It's incrementing until it finds '\0', or until uVar4 is 0.
      // But uVar4 is 0xffffffff, so it will never be 0.

      auth = malloc(4);
			auth[0] = 0;
      
      //uVar4 = ~uVar4 - 1;
      // Reverse the value of uVar4 and subtract 1.
      // So it's the length of the string.

      uVar4 = strlen(input + 5);
      // uVar8 = uVar4 < 0x1e;
      // uVar11 = uVar4 == 0x1e;

      // 0x1f is 31 in decimal.
      if (uVar4 < 31) {
        strcpy((char *)auth, input + 5);
      }
    }

    // iVar3 = 5;
    // pbVar5 = local_90;
    // pbVar6 = (u_int8_t *)"reset";
    // do {
    //   if (iVar3 == 0) break;
    //   iVar3 = iVar3 + -1;
    //   uVar8 = *pbVar5 < *pbVar6;
    //   uVar11 = *pbVar5 == *pbVar6;
    //   pbVar5 = pbVar5 + bVar12 * -2 + 1;
    //   pbVar6 = pbVar6 + bVar12 * -2 + 1;
    // } while (uVar11);
    // uVar9 = 0;
    // uVar8 = (!uVar8 && !uVar11) == uVar8;
    // if (uVar8) {
    //   free(auth);
    // }
    // This code above compares the input string character by character with "reset".
    // If they are equal, it frees the memory allocated to auth.

    if (strncmp(input, "reset", 5) == 0) {
      free(auth);
    }

    // iVar3 = 6;
    // pbVar5 = local_90;
    // pbVar6 = (u_int8_t *)"service";
    // do {
    //   if (iVar3 == 0) break;
    //   iVar3 = iVar3 + -1;
    //   uVar9 = *pbVar5 < *pbVar6;
    //   uVar8 = *pbVar5 == *pbVar6;
    //   pbVar5 = pbVar5 + bVar12 * -2 + 1;
    //   pbVar6 = pbVar6 + bVar12 * -2 + 1;
    // } while (uVar8);
    // uVar11 = 0;
    // uVar8 = (!(bool)uVar9 && !uVar8) == (bool)uVar9;
    // if (uVar8) {
    //   uVar11 = (u_int8_t *)0xfffffff8 < local_90;
    //   uVar8 = acStack_89 == (char *)0x0;
    //   service = strdup(acStack_89);
    // }
    // This code compares the input string character by character with "service".
    // If they are equal, it duplicates the string acStack_89 and assigns it to service.
    
    if (strncmp(input, "service", 7) == 0) {
        // service = strdup(acStack_89);
        // strdup duplicates the string acStack_89 and assigns it to service,
        // but if we look at the decompilation in Ghidra, we can see that
        // acStack_89 = EAX + 0x7
        // So it's more likely that acStack_89 is the user input + 7.
        service = strdup(input + 7);
    }

    // iVar3 = 5;
    // pbVar5 = local_90;
    // pbVar6 = (u_int8_t *)"login";
    // do {
    //   if (iVar3 == 0) break;
    //   iVar3 = iVar3 + -1;
    //   uVar11 = *pbVar5 < *pbVar6;
    //   uVar8 = *pbVar5 == *pbVar6;
    //   pbVar5 = pbVar5 + bVar12 * -2 + 1;
    //   pbVar6 = pbVar6 + bVar12 * -2 + 1;
    // } while (uVar8);
    // if ((!uVar11 && !uVar8) == uVar11) {
    //   if (auth[8] == 0) {
    //     fwrite("Password:\n",1,10,stdout);
    //   }
    //   else {
    //     system("/bin/sh");
    //   }
    // }
    // This code compares the input string character by character with "login".
    // If they are equal, it checks if auth[8] is 0 and then prints "Password:" or opens a shell.

    if (strncmp(input, "login", 5) == 0) {
        // if (auth != NULL && ((char *)auth)[8] == 0) {
        // if we look at the decompilation in Ghidra, we can see that 
        // MOV        EAX,[auth]
        // and dword ptr [EAX + 0x20]
        // We can think that EAX is the auth address, 0x20 == 32 in decimal.
        // So the condition is auth[32] == 0.
        if (auth != NULL && auth[32] == 0) {
            fwrite("Password:\n", 1, 10, stdout);
        } else {
            system("/bin/sh");
        }
    }
  } while( true );
}

