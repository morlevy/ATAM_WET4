

int count = 0;

int foo()
{
  return (count++);
}

int bar(int n)
{
  int lim = n*n;
  int inc;
  while(n < lim)
  {
     inc = (count % 7) ? (count % 7) : 1;
     n += inc;
     foo();
  }
  return (n % lim);
}

int rec_foo(int param, int orig_param)
{
  if(!(param % 6))
  {
    return count;
  }
  count++;
  return rec_foo((param+orig_param)%6, orig_param);
}

int rec_bar(int ord, int orig_ord)
{
  for(int i = 1; i < 6; i++)
  {
    count = 0;
    if(!(ord % rec_foo(i,i)))
    {
      return (ord/orig_ord);
    }
  }
  return rec_bar(ord + orig_ord, orig_ord);
}

int mut_rec_bar();

int mut_rec_foo()
{
  if(count == 0) { return 1; }
  else if(count < 0) { count++; }
  else {count--;}
  return mut_rec_bar();
}

int mut_rec_bar()
{
  if(count == 0) { return 0; }
  else if(count < 0) { count++; }
  else {count--;}
  return mut_rec_foo();
}

int call_f_ptr(int (*f)(int), int param)
{
  f(param);
  return -2;
}