
int main()
{
  foo();
  bar(42);
  bar(6);
  bar(9);
  bar(bar(5));
  return 0;
}