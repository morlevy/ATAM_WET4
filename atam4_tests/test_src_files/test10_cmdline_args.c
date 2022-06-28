
int main(int argc, char** argv)
{
  if(argc != 5)
    return 1;
  if(*(*(argv+1)) == 'D')
  {
     foo();
  }
  for(int i = 0; i < argc; i++)
  {
    bar(*(*(argv+i) + i));
  }
  return 0;
}