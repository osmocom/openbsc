probe process("/usr/lib/libsqlite3.so.0.8.6").function("sqlite3_get_table")
{
  a = user_string($zSql);
  printf("sqlite3_get_table called '%s'\n", a);
}
