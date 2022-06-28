
extern int count;

int main()
{
  count = 5;
  mut_rec_foo(0);
  count = -5;
  mut_rec_bar(0);
  return 0;
}