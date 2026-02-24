/*
 * Kiseki OS - IOKit Property Table Implementation
 *
 * Flat-array key-value store replacing OSDictionary for IOKit registry
 * properties. All storage is inline (no heap allocations).
 *
 * Reference: XNU libkern/c++/OSDictionary.cpp
 */

#include <iokit/io_property.h>
#include <iokit/iokit_types.h>
#include <kern/kprintf.h>

/* ============================================================================
 * String Helpers (freestanding — no libc)
 * ============================================================================ */

static int
prop_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static void
prop_strncpy(char *dst, const char *src, uint32_t max)
{
    uint32_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static void
prop_memcpy(void *dst, const void *src, uint32_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < len; i++)
        d[i] = s[i];
}

static int
prop_memcmp(const void *a, const void *b, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)a;
    const uint8_t *q = (const uint8_t *)b;
    for (uint32_t i = 0; i < len; i++) {
        if (p[i] != q[i])
            return (int)p[i] - (int)q[i];
    }
    return 0;
}

/* ============================================================================
 * Find entry by key (internal)
 * ============================================================================ */

static struct io_prop_entry *
prop_find(const struct io_prop_table *table, const char *key)
{
    for (uint32_t i = 0; i < IO_PROP_TABLE_MAX; i++) {
        if (table->entries[i].key[0] != '\0' &&
            prop_strcmp(table->entries[i].key, key) == 0)
            return (struct io_prop_entry *)&table->entries[i];
    }
    return NULL;
}

/* Find a free slot (internal) */
static struct io_prop_entry *
prop_find_free(struct io_prop_table *table)
{
    for (uint32_t i = 0; i < IO_PROP_TABLE_MAX; i++) {
        if (table->entries[i].key[0] == '\0')
            return &table->entries[i];
    }
    return NULL;
}

/* ============================================================================
 * io_prop_table_init
 * ============================================================================ */

void
io_prop_table_init(struct io_prop_table *table)
{
    for (uint32_t i = 0; i < IO_PROP_TABLE_MAX; i++) {
        table->entries[i].key[0] = '\0';
        table->entries[i].value.type = IO_PROP_NONE;
    }
    table->count = 0;
}

/* ============================================================================
 * Set operations
 * ============================================================================ */

IOReturn
io_prop_set_string(struct io_prop_table *table,
                   const char *key, const char *value)
{
    if (!table || !key || !value)
        return kIOReturnBadArgument;

    struct io_prop_entry *e = prop_find(table, key);
    if (!e) {
        e = prop_find_free(table);
        if (!e)
            return kIOReturnNoSpace;
        table->count++;
    }

    prop_strncpy(e->key, key, IO_PROP_KEY_MAX);
    e->value.type = IO_PROP_STRING;
    prop_strncpy(e->value.u.string, value, IO_PROP_STRING_MAX);
    return kIOReturnSuccess;
}

IOReturn
io_prop_set_number(struct io_prop_table *table,
                   const char *key, uint64_t value)
{
    if (!table || !key)
        return kIOReturnBadArgument;

    struct io_prop_entry *e = prop_find(table, key);
    if (!e) {
        e = prop_find_free(table);
        if (!e)
            return kIOReturnNoSpace;
        table->count++;
    }

    prop_strncpy(e->key, key, IO_PROP_KEY_MAX);
    e->value.type = IO_PROP_NUMBER;
    e->value.u.number = value;
    return kIOReturnSuccess;
}

IOReturn
io_prop_set_bool(struct io_prop_table *table,
                 const char *key, bool value)
{
    if (!table || !key)
        return kIOReturnBadArgument;

    struct io_prop_entry *e = prop_find(table, key);
    if (!e) {
        e = prop_find_free(table);
        if (!e)
            return kIOReturnNoSpace;
        table->count++;
    }

    prop_strncpy(e->key, key, IO_PROP_KEY_MAX);
    e->value.type = IO_PROP_BOOL;
    e->value.u.boolean = value;
    return kIOReturnSuccess;
}

IOReturn
io_prop_set_data(struct io_prop_table *table,
                 const char *key, const void *data, uint32_t length)
{
    if (!table || !key || !data)
        return kIOReturnBadArgument;
    if (length > IO_PROP_DATA_MAX)
        return kIOReturnBadArgument;

    struct io_prop_entry *e = prop_find(table, key);
    if (!e) {
        e = prop_find_free(table);
        if (!e)
            return kIOReturnNoSpace;
        table->count++;
    }

    prop_strncpy(e->key, key, IO_PROP_KEY_MAX);
    e->value.type = IO_PROP_DATA;
    prop_memcpy(e->value.u.data.bytes, data, length);
    e->value.u.data.length = length;
    return kIOReturnSuccess;
}

/* ============================================================================
 * Get operations
 * ============================================================================ */

const struct io_prop_value *
io_prop_get(const struct io_prop_table *table, const char *key)
{
    if (!table || !key)
        return NULL;

    const struct io_prop_entry *e = (const struct io_prop_entry *)prop_find(table, key);
    if (!e)
        return NULL;
    return &e->value;
}

const char *
io_prop_get_string(const struct io_prop_table *table, const char *key)
{
    const struct io_prop_value *v = io_prop_get(table, key);
    if (!v || v->type != IO_PROP_STRING)
        return NULL;
    return v->u.string;
}

bool
io_prop_get_number(const struct io_prop_table *table,
                   const char *key, uint64_t *out)
{
    const struct io_prop_value *v = io_prop_get(table, key);
    if (!v || v->type != IO_PROP_NUMBER)
        return false;
    if (out)
        *out = v->u.number;
    return true;
}

/* ============================================================================
 * Remove
 * ============================================================================ */

IOReturn
io_prop_remove(struct io_prop_table *table, const char *key)
{
    if (!table || !key)
        return kIOReturnBadArgument;

    struct io_prop_entry *e = prop_find(table, key);
    if (!e)
        return kIOReturnNotFound;

    e->key[0] = '\0';
    e->value.type = IO_PROP_NONE;
    table->count--;
    return kIOReturnSuccess;
}

/* ============================================================================
 * Copy
 * ============================================================================ */

void
io_prop_copy(struct io_prop_table *dst, const struct io_prop_table *src)
{
    io_prop_table_init(dst);
    for (uint32_t i = 0; i < IO_PROP_TABLE_MAX; i++) {
        if (src->entries[i].key[0] != '\0') {
            prop_memcpy(&dst->entries[i], &src->entries[i],
                        sizeof(struct io_prop_entry));
            dst->count++;
        }
    }
}

/* ============================================================================
 * Match
 *
 * Checks whether all key-value pairs in 'match' exist in 'target'
 * with identical values. Used by the IOKit matching algorithm.
 *
 * Reference: XNU IOService::passiveMatch() / IOService::compareProperty()
 * ============================================================================ */

static bool
prop_value_equal(const struct io_prop_value *a, const struct io_prop_value *b)
{
    if (a->type != b->type)
        return false;

    switch (a->type) {
    case IO_PROP_STRING:
        return prop_strcmp(a->u.string, b->u.string) == 0;
    case IO_PROP_NUMBER:
        return a->u.number == b->u.number;
    case IO_PROP_BOOL:
        return a->u.boolean == b->u.boolean;
    case IO_PROP_DATA:
        if (a->u.data.length != b->u.data.length)
            return false;
        return prop_memcmp(a->u.data.bytes, b->u.data.bytes,
                           a->u.data.length) == 0;
    case IO_PROP_NONE:
        return true;
    }
    return false;
}

bool
io_prop_match(const struct io_prop_table *target,
              const struct io_prop_table *match)
{
    if (!target || !match)
        return false;

    for (uint32_t i = 0; i < IO_PROP_TABLE_MAX; i++) {
        if (match->entries[i].key[0] == '\0')
            continue;

        /*
         * Special handling for IOProviderClass:
         *
         * On XNU, IOServiceMatching("Foo") creates a matching dict
         * with {"IOProviderClass": "Foo"}. The matching engine doesn't
         * look for a literal "IOProviderClass" property on the service.
         * Instead, it compares the value against the service's class
         * name (via OSMetaClass::isKindOf).
         *
         * In Kiseki, each service has an "IOClass" property set during
         * io_registry_entry_init(). We map IOProviderClass lookups to
         * the IOClass property for matching.
         *
         * Reference: XNU IOService::passiveMatch()
         */
        if (prop_strcmp(match->entries[i].key, kIOProviderClassKey) == 0) {
            /* Match against the target's IOClass property instead */
            const struct io_prop_value *class_val =
                io_prop_get(target, kIOClassKey);
            if (!class_val)
                return false;
            if (!prop_value_equal(class_val, &match->entries[i].value))
                return false;
            continue;
        }

        /* Standard property match: key must exist with same value */
        const struct io_prop_value *tv = io_prop_get(target,
                                                      match->entries[i].key);
        if (!tv)
            return false;
        if (!prop_value_equal(tv, &match->entries[i].value))
            return false;
    }
    return true;
}
