void m(void *param_1,int param_2,char *param_3,int param_4,int param_5)
{
  time_t param2;
  
  param2 = time((time_t *)0);
  printf("%s - %d\n", c, param2);
  return;
}


int main(int ac,char **av)

{
  int *ptr1;
  void *ptr;
  int *ptr2;
  FILE *__stream;
  
  ptr1 = (int *)malloc(8);
  *ptr1 = 1;
  ptr = malloc(8);
  ptr1[1] = ptr;
  ptr2 = (int *)malloc(8);
  *ptr2 = 2;
  ptr = malloc(8);
  ptr2[1] = ptr;
  strcpy((char *)ptr1[1],av[1]);
  strcpy((char *)ptr2[1],av[2]);
  __stream = fopen("/home/user/level8/.pass","r");
  fgets(c, 68, __stream);
  puts("~~"); 
  return 0;
}