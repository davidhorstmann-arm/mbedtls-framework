/**
 * \file memory.c
 *
 * \brief   Helper functions related to testing memory management.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <test/helpers.h>
#include <test/macros.h>
#include <test/memory.h>

#if defined(MBEDTLS_TEST_MEMORY_CAN_POISON)
#include <sanitizer/asan_interface.h>
#include <stdint.h>
#endif

#if defined(MBEDTLS_TEST_MEMORY_CAN_POISON)

_Thread_local unsigned int mbedtls_test_memory_poisoning_count = 0;

_Thread_local poisoned_buf_t *poisoned_bufs_head;

static void align_for_asan(const unsigned char **p_ptr, size_t *p_size)
{
    uintptr_t start = (uintptr_t) *p_ptr;
    uintptr_t end = start + (uintptr_t) *p_size;
    /* ASan can only poison regions with 8-byte alignment, and only poisons a
     * region if it's fully within the requested range. We want to poison the
     * whole requested region and don't mind a few extra bytes. Therefore,
     * align start down to an 8-byte boundary, and end up to an 8-byte
     * boundary. */
    start = start & ~(uintptr_t) 7;
    end = (end + 7) & ~(uintptr_t) 7;
    *p_ptr = (const unsigned char *) start;
    *p_size = end - start;
}

static int mbedtls_test_memory_is_in_poisoned_list(const unsigned char *ptr)
{
    poisoned_buf_t *p_buf = poisoned_bufs_head;
    while (p_buf != NULL && p_buf->ptr != ptr) {
        p_buf = p_buf->next;
    }
    if (p_buf != NULL) {
        return 1;
    }
    return 0;
}

static int mbedtls_test_memory_poisoned_list_add(const unsigned char *ptr)
{
    poisoned_buf_t *new_p_buf = (poisoned_buf_t *) mbedtls_calloc(1, sizeof(*new_p_buf));

    if (new_p_buf == NULL) {
        return -1;
    }

    new_p_buf->ptr = ptr;
    new_p_buf->next = poisoned_bufs_head;
    poisoned_bufs_head = new_p_buf;

    return 0;
}

static void mbedtls_test_memory_poisoned_list_remove(const unsigned char *ptr)
{
    poisoned_buf_t *p_buf = poisoned_bufs_head;
    poisoned_buf_t *p_buf_prev = NULL;

    while (p_buf != NULL && p_buf->ptr != ptr) {
        p_buf_prev = p_buf;
        p_buf = p_buf->next;
    }

    if (p_buf != NULL) {
        if (p_buf_prev == NULL) {
            poisoned_bufs_head = p_buf->next;
        } else {
            p_buf_prev->next = p_buf->next;
        }
        mbedtls_free(p_buf);
        p_buf = NULL;
    }
}

void mbedtls_test_memory_poison(const unsigned char *ptr, size_t size)
{
    if (mbedtls_test_memory_poisoning_count == 0) {
        return;
    }
    if (size == 0) {
        return;
    }
    align_for_asan(&ptr, &size);
    __asan_poison_memory_region(ptr, size);
}

void mbedtls_test_memory_unpoison(const unsigned char *ptr, size_t size)
{
    if (size == 0) {
        return;
    }
    align_for_asan(&ptr, &size);
    __asan_unpoison_memory_region(ptr, size);
}

void mbedtls_test_memory_poison_hook(const unsigned char *ptr, size_t size)
{
    if (mbedtls_test_memory_is_in_poisoned_list(ptr)) {
        mbedtls_test_memory_poison(ptr, size);
    }
}

void mbedtls_test_memory_unpoison_hook(const unsigned char *ptr, size_t size)
{
    if (mbedtls_test_memory_is_in_poisoned_list(ptr)) {
        mbedtls_test_memory_unpoison(ptr, size);
    }
}

void mbedtls_test_memory_poison_wrapper(const unsigned char *ptr, size_t size)
{
    mbedtls_test_memory_poisoned_list_add(ptr);
    mbedtls_test_memory_poison(ptr, size);
}

void mbedtls_test_memory_unpoison_wrapper(const unsigned char *ptr, size_t size)
{
    mbedtls_test_memory_unpoison(ptr, size);
    mbedtls_test_memory_poisoned_list_remove(ptr);
}

#endif /* Memory poisoning */
