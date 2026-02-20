# ============================================================================
# Kiseki OS - vi (levee)
# ============================================================================
# Levee is a small vi clone by David L. Parsons.
# BSD-style license.
# ============================================================================

PROG := vi
SRCS := blockio.c display.c editcor.c exec.c find.c globals.c \
        home.c insert.c main.c misc.c modify.c move.c tag.c undo.c \
        unixcall.c ucsd.c version.c

include ../coreutils.mk

# Levee-specific flags - suppress warnings from original code
CFLAGS += -Wno-int-to-void-pointer-cast \
          -Wno-void-pointer-to-int-cast \
          -Wno-implicit-function-declaration \
          -Wno-parentheses \
          -Wno-deprecated-non-prototype \
          -Wno-string-plus-int \
          -Wno-dangling-else \
          -Wno-format \
          -Wno-uninitialized

# Allow undefined symbols - they'll be resolved at runtime by Kiseki's dyld
# Our termcap functions (tgetent, tgetstr, etc.) are in libSystem.B.dylib
LDFLAGS += -Wl,-undefined,dynamic_lookup
