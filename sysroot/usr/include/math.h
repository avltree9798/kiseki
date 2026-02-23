/*
 * Kiseki OS - Math Functions
 */

#ifndef _LIBSYSTEM_MATH_H
#define _LIBSYSTEM_MATH_H

/* Infinity and NaN */
#define HUGE_VAL    __builtin_huge_val()
#define INFINITY    __builtin_inf()
#define NAN         __builtin_nan("")

/* Classification */
#define isnan(x)    __builtin_isnan(x)
#define isinf(x)    __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)

/* Basic math functions */
double ldexp(double x, int exp);
double frexp(double x, int *exp);
double fabs(double x);
double floor(double x);
double ceil(double x);
double sqrt(double x);
double pow(double x, double y);
double log(double x);
double log10(double x);
double exp(double x);
double sin(double x);
double cos(double x);
double tan(double x);
double atan(double x);
double atan2(double y, double x);

/* Float versions */
float ldexpf(float x, int exp);
float fabsf(float x);
float floorf(float x);
float ceilf(float x);
float sqrtf(float x);

#endif /* _LIBSYSTEM_MATH_H */
