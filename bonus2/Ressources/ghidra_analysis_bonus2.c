void greetuser(void)
{
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined local_3a;
  
  if (language == 1) {
    local_4c._0_1_ = 'H';
    local_4c._1_1_ = 'y';
    local_4c._2_1_ = 'v';
    local_4c._3_1_ = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    local_44._0_1_ = 'p';
    local_44._1_1_ = -0x3d;
    local_44._2_1_ = -0x5c;
    local_44._3_1_ = 'i';
    local_40 = 0xc3a4c376;
    local_3c = 0x20a4;
    local_3a = 0;
  }
  else if (language == 2) {
    local_4c._0_1_ = 'G';
    local_4c._1_1_ = 'o';
    local_4c._2_1_ = 'e';
    local_4c._3_1_ = 'd';
    local_48._0_1_ = 'e';
    local_48._1_1_ = 'm';
    local_48._2_1_ = 'i';
    local_48._3_1_ = 'd';
    local_44._0_1_ = 'd';
    local_44._1_1_ = 'a';
    local_44._2_1_ = 'g';
    local_44._3_1_ = '!';
    local_40 = CONCAT22(local_40._2_2_,0x20);
  }
  else if (language == 0) {
    local_4c._0_1_ = 'H';
    local_4c._1_1_ = 'e';
    local_4c._2_1_ = 'l';
    local_4c._3_1_ = 'l';
    local_48._0_3_ = 0x206f;
  }
  strcat((char *)&local_4c,&stack0x00000004);
  puts((char *)&local_4c);
  return;
}
