/*
 * Kiseki OS - String Operations
 */

#ifndef _LIBSYSTEM_STRING_H
#define _LIBSYSTEM_STRING_H

#include <types.h>

/* String length and comparison */
size_t  strlen(const char *s);
int     strcmp(const char *s1, const char *s2);
int     strncmp(const char *s1, const char *s2, size_t n);

/* String copy */
char   *strcpy(char *dst, const char *src);
char   *strncpy(char *dst, const char *src, size_t n);

/* String concatenation */
char   *strcat(char *dst, const char *src);
char   *strncat(char *dst, const char *src, size_t n);

/* Memory operations */
void   *memcpy(void *dst, const void *src, size_t n);
void   *memmove(void *dst, const void *src, size_t n);
void   *memset(void *s, int c, size_t n);
int     memcmp(const void *s1, const void *s2, size_t n);
void   *memchr(const void *s, int c, size_t n);

/* String search */
char   *strchr(const char *s, int c);
char   *strrchr(const char *s, int c);
char   *strstr(const char *haystack, const char *needle);
char   *strdup(const char *s);
char   *strndup(const char *s, size_t n);

/* Tokenize */
char   *strtok(char *str, const char *delim);
char   *strtok_r(char *str, const char *delim, char **saveptr);

/* Error string */
char   *strerror(int errnum);

/* Span / break */
size_t  strspn(const char *s, const char *accept);
size_t  strcspn(const char *s, const char *reject);
char   *strpbrk(const char *s, const char *accept);

#endif /* _LIBSYSTEM_STRING_H */
