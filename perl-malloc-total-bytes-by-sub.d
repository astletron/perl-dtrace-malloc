#!/usr/sbin/dtrace -s

dtrace:::BEGIN {
  depth = 0
}

perl$target:::sub-entry
{
  self->sub = copyinstr(arg0);
  self->file = copyinstr(arg1);

  sdepth[depth] = self->sub;
  fdepth[depth++] = self->file;
}

perl$target:::sub-return
{
  self->sub = sdepth[--depth];
  self->file = fdepth[depth];
}

pid$target::malloc:entry
{
  @[self->file, self->sub] = sum( arg0 );
}

