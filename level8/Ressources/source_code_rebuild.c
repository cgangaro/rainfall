#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int *auth = NULL;
char *service = NULL;

int main(void)
{
  u_int8_t bVar12;
  char *pcVar2;
  char local_90 [5];
  bool bVar7;
  bool bVar10;
  int iVar3;
  u_int8_t *pbVar6;
  char cVar1;
  uint uVar4;
  u_int8_t *pbVar5;
  bool uVar8;
  u_int8_t uVar9;
  bool uVar11;
  char local_8b [2];
  char acStack_89 [125];
  
  bVar12 = 0;
  do {
    printf("%p, %p\n", auth, service);
    pcVar2 = fgets((char *)local_90,0x80,stdin);
    bVar7 = false;
    bVar10 = pcVar2 == (char *)0x0;
    if (bVar10) {
      return 0;
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (u_int8_t *)"auth ";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pbVar5 < *pbVar6;
      bVar10 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + bVar12 * -2 + 1;
      pbVar6 = pbVar6 + bVar12 * -2 + 1;
    } while (bVar10);
    uVar8 = 0;
    uVar11 = (!bVar7 && !bVar10) == bVar7;
    if (uVar11) {
      auth = (int *)malloc(4);
      *auth = 0;
      uVar4 = 0xffffffff;
      pcVar2 = local_8b;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + (uint)bVar12 * -2 + 1;
      } while (cVar1 != '\0');
      uVar4 = ~uVar4 - 1;
      uVar8 = uVar4 < 0x1e;
      uVar11 = uVar4 == 0x1e;
      if (uVar4 < 0x1f) {
        strcpy((char *)auth,local_8b + 5);
      }
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (u_int8_t *)"reset";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar8 = *pbVar5 < *pbVar6;
      uVar11 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + bVar12 * -2 + 1;
      pbVar6 = pbVar6 + bVar12 * -2 + 1;
    } while (uVar11);
    uVar9 = 0;
    uVar8 = (!uVar8 && !uVar11) == uVar8;
    if (uVar8) {
      free(auth);
    }
    iVar3 = 6;
    pbVar5 = local_90;
    pbVar6 = (u_int8_t *)"service";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar9 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + bVar12 * -2 + 1;
      pbVar6 = pbVar6 + bVar12 * -2 + 1;
    } while (uVar8);
    uVar11 = 0;
    uVar8 = (!(bool)uVar9 && !uVar8) == (bool)uVar9;
    if (uVar8) {
      uVar11 = (u_int8_t *)0xfffffff8 < local_90;
      uVar8 = acStack_89 == (char *)0x0;
      service = strdup(acStack_89);
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (u_int8_t *)"login";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar11 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + bVar12 * -2 + 1;
      pbVar6 = pbVar6 + bVar12 * -2 + 1;
    } while (uVar8);
    if ((!uVar11 && !uVar8) == uVar11) {
      if (auth[8] == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while( true );
}

