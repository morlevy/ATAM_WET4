extern int count;

int main()
{
  count = 0;
  rec_foo(5,5);
  rec_bar(1,1);
  rec_bar(7,7);
  rec_bar(20,20);
  return 0;
}