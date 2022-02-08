/** 
 *   @file ex_string.c
 *   @brief This file implements some libcs string functions, which are not available in Linxu Kernel
 *   @author cfho
 *   @version 1
 *   @date  2013-0714
 *   @bug none
 *   @warning none
*/
/** -------------------------------------------------------------------------
              INCLUDE HEADER FILES                
  -------------------------------------------------------------------------*/
typedef  int size_t;
/*
 * C standard string function: find leftmost instance of a character
 * in a string.
 */
char *
strchr(const char *s, int ch)
{
        /* scan from left to right */
        while (*s) {
                /* if we hit it, return it */
                if (*s==ch) {
                        return (char *)s;
                }
                s++;
        }

        /* if we were looking for the 0, return that */
        if (*s==ch) {
                return (char *)s;
        }

        /* didn't find it */
        return 0;
}

/* This uses strchr, strchr should be in assembler */
#if 0
char *strpbrk(str, set)
register char *str;
char *set;
#endif
char *strpbrk( char *str, char *set)
{
  while (*str != '\0')
    if (strchr(set, *str) == 0)
      ++str;
    else
      return (char *) str;
 
  return 0;
}

/* Return the length of the maximum initial segment
   of S which contains only characters in ACCEPT.  */
#if 0
size_t
strspn(s, accept)
char *s;
char *accept;
#endif
int strspn(char *s, char *accept)
{
  register char *p;
  register char *a;
  register size_t count = 0;

  for (p = s; *p != '\0'; ++p)
    {
      for (a = accept; *a != '\0'; ++a)
    if (*p == *a)
      break;
      if (*a == '\0')
    return count;
      else
    ++count;
    }

  return count;
}


static char *olds = 0;

/* Parse S into tokens separated by characters in DELIM.
   If S is NULL, the last string strtok() was called with is
   used.  For example:
    char s[] = "-abc=-def";
    x = strtok(s, "-");        // x = "abc"
    x = strtok(NULL, "=-");        // x = "def"
    x = strtok(NULL, "=");        // x = NULL
        // s = "abc\0-def\0"
*/
#if 0
char *
strtok(s, delim)
register char *s;
register char *delim;
#endif
char *strtok(register char *s, register char *delim)
{
  char *token;

  if (s == 0)
    {
      if (olds == 0)
    {
      return 0;
    }
      else
    s = olds;
    }

  /* Scan leading delimiters.  */
  s += strspn(s, delim);
  if (*s == '\0')
    {
      olds = 0;
      return 0;
    }

  /* Find the end of the token.  */
  token = s;
  s = strpbrk(token, delim);
  if (s == 0)
    /* This token finishes the string.  */
    olds = 0;
  else
    {
      /* Terminate the token and make OLDS point past it.  */
      *s = '\0';
      olds = s + 1;
    }
  return token;
}

