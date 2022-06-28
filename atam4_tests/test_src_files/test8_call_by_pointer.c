extern int bar(int n);

int main()
{
  foo();
  call_f_ptr(&bar,0x45);
  return 0;
}