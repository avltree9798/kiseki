/*
 * Kiseki OS - IOKit Property Table
 *
 * Replaces XNU's OSDictionary for storing IOKit registry properties.
 * Each IORegistryEntry has a property table that stores key-value pairs
 * used for driver matching, configuration, and user queries.
 *
 * Properties are stored as tagged unions in a flat array (no heap).
 * Keys are string names; values can be strings, numbers, booleans,
 * or raw data blobs.
 *
 * Reference: XNU libkern/c++/OSDictionary.cpp,
 *            iokit/Kernel/IORegistryEntry.cpp (getProperty, setProperty)
 */

#ifndef _IOKIT_IO_PROPERTY_H
#define _IOKIT_IO_PROPERTY_H

#include <iokit/iokit_types.h>
#include <kern/sync.h>

/* ============================================================================
 * Property Table Limits
 * ============================================================================ */

#define IO_PROP_TABLE_MAX       64      /* Max properties per registry entry */
#define IO_PROP_KEY_MAX         64      /* Max key string length (incl. NUL) */
#define IO_PROP_STRING_MAX      128     /* Max string value length (incl. NUL) */
#define IO_PROP_DATA_MAX        256     /* Max raw data blob size */

/* ============================================================================
 * Property Value Types
 *
 * Mirrors the OSDictionary value types: OSString, OSNumber, OSBoolean,
 * OSData. We use a tagged union instead of C++ dynamic dispatch.
 * ============================================================================ */

typedef enum {
    IO_PROP_NONE    = 0,    /* Empty slot */
    IO_PROP_STRING  = 1,    /* NUL-terminated string */
    IO_PROP_NUMBER  = 2,    /* 64-bit unsigned integer */
    IO_PROP_BOOL    = 3,    /* Boolean (true/false) */
    IO_PROP_DATA    = 4,    /* Raw byte data blob */
} io_prop_type_t;

/* ============================================================================
 * io_prop_value - Tagged union for a property value
 * ============================================================================ */

struct io_prop_value {
    io_prop_type_t  type;

    union {
        /* IO_PROP_STRING */
        char            string[IO_PROP_STRING_MAX];

        /* IO_PROP_NUMBER */
        uint64_t        number;

        /* IO_PROP_BOOL */
        bool            boolean;

        /* IO_PROP_DATA */
        struct {
            uint8_t     bytes[IO_PROP_DATA_MAX];
            uint32_t    length;
        } data;
    } u;
};

/* ============================================================================
 * io_prop_entry - One key-value pair in a property table
 * ============================================================================ */

struct io_prop_entry {
    char                key[IO_PROP_KEY_MAX];   /* Property key */
    struct io_prop_value value;                  /* Property value */
};

/* ============================================================================
 * io_prop_table - Collection of properties for a registry entry
 *
 * Flat array of io_prop_entry slots. Unused slots have key[0] == '\0'.
 * Thread-safety is provided by the owning IORegistryEntry's lock.
 * ============================================================================ */

struct io_prop_table {
    struct io_prop_entry    entries[IO_PROP_TABLE_MAX];
    uint32_t                count;      /* Number of active entries */
};

/* ============================================================================
 * Property Table API
 * ============================================================================ */

/*
 * io_prop_table_init - Initialise a property table (all slots empty).
 */
void io_prop_table_init(struct io_prop_table *table);

/*
 * io_prop_set_string - Set a string property.
 *
 * If the key already exists, its value is overwritten.
 * Returns kIOReturnSuccess or kIOReturnNoSpace if the table is full.
 */
IOReturn io_prop_set_string(struct io_prop_table *table,
                            const char *key, const char *value);

/*
 * io_prop_set_number - Set a numeric property.
 */
IOReturn io_prop_set_number(struct io_prop_table *table,
                            const char *key, uint64_t value);

/*
 * io_prop_set_bool - Set a boolean property.
 */
IOReturn io_prop_set_bool(struct io_prop_table *table,
                          const char *key, bool value);

/*
 * io_prop_set_data - Set a raw data property.
 */
IOReturn io_prop_set_data(struct io_prop_table *table,
                          const char *key, const void *data, uint32_t length);

/*
 * io_prop_get - Look up a property by key.
 *
 * Returns a pointer to the io_prop_value if found, NULL otherwise.
 * The caller must not free or modify the returned pointer (it points
 * into the table's internal storage).
 *
 * Reference: XNU IORegistryEntry::getProperty()
 */
const struct io_prop_value *io_prop_get(const struct io_prop_table *table,
                                        const char *key);

/*
 * io_prop_get_string - Convenience: look up a string property.
 *
 * Returns the string value, or NULL if not found or wrong type.
 */
const char *io_prop_get_string(const struct io_prop_table *table,
                               const char *key);

/*
 * io_prop_get_number - Convenience: look up a numeric property.
 *
 * Returns true and writes the value to *out if found. Returns false
 * if not found or wrong type.
 */
bool io_prop_get_number(const struct io_prop_table *table,
                        const char *key, uint64_t *out);

/*
 * io_prop_remove - Remove a property by key.
 *
 * Returns kIOReturnSuccess or kIOReturnNotFound.
 */
IOReturn io_prop_remove(struct io_prop_table *table, const char *key);

/*
 * io_prop_copy - Deep copy all properties from src to dst.
 *
 * The destination table is cleared first.
 */
void io_prop_copy(struct io_prop_table *dst, const struct io_prop_table *src);

/*
 * io_prop_match - Check if all properties in 'match' exist in 'target'
 *                 with matching values.
 *
 * Used by the IOKit matching algorithm: a matching dictionary's properties
 * must all be present in the service's property table with equal values.
 *
 * Reference: XNU IOService::compareProperty()
 *
 * Returns true if all properties in match are found in target with
 * identical values, false otherwise.
 */
bool io_prop_match(const struct io_prop_table *target,
                   const struct io_prop_table *match);

#endif /* _IOKIT_IO_PROPERTY_H */
