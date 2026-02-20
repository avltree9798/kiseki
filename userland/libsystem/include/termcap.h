/*
 * Kiseki OS - termcap.h
 *
 * Minimal termcap interface for terminal capability handling.
 * Implementation is in libSystem.B.dylib.
 */

#ifndef _TERMCAP_H
#define _TERMCAP_H

/*
 * tgetent - Load terminal entry from termcap database.
 *
 * @bp:   Buffer for terminal entry (unused in Kiseki - we use VT100)
 * @name: Terminal name (e.g., "vt100", "xterm")
 *
 * Returns: 1 on success, 0 if not found, -1 on error.
 */
int tgetent(char *bp, const char *name);

/*
 * tgetstr - Get string capability.
 *
 * @id:   Two-character capability name (e.g., "cm", "cl")
 * @area: Pointer to buffer pointer for storing the string
 *
 * Returns: Pointer to the capability string, or NULL if not found.
 */
char *tgetstr(const char *id, char **area);

/*
 * tgetnum - Get numeric capability.
 *
 * @id: Two-character capability name (e.g., "li", "co")
 *
 * Returns: The numeric value, or -1 if not found.
 */
int tgetnum(const char *id);

/*
 * tgetflag - Get boolean capability.
 *
 * @id: Two-character capability name
 *
 * Returns: 1 if present, 0 if not.
 */
int tgetflag(const char *id);

/*
 * tgoto - Produce cursor motion string.
 *
 * @cm:  Cursor motion capability string
 * @col: Column (0-based)
 * @row: Row (0-based)
 *
 * Returns: Pointer to static buffer with formatted string.
 */
char *tgoto(const char *cm, int col, int row);

/*
 * tputs - Output a termcap string with padding.
 *
 * @str:     String to output
 * @affcnt:  Number of lines affected (for padding calculation)
 * @putc:    Function to output each character
 *
 * Returns: 0 on success.
 */
int tputs(const char *str, int affcnt, int (*putc)(int));

#endif /* _TERMCAP_H */
