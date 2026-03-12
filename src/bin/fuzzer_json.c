#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <talloc.h>
#include <json-c/json.h>

/* Forward declarations for FreeRADIUS types to avoid header complexity */
typedef struct fr_jpath_node_s fr_jpath_node_t;

/* External declarations for functions */
extern ssize_t fr_jpath_parse(void *ctx, fr_jpath_node_t **head, 
                               char const *in, size_t inlen);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *ctx = NULL;
    json_object *json_obj = NULL;
    char *json_str = NULL;
    char *jpath_str = NULL;
    fr_jpath_node_t *jpath_head = NULL;
    size_t split_point;

    /* Need at least 2 bytes */
    if (size < 2) {
        return 0;
    }

    /* Limit input size to prevent timeouts */
    if (size > 8192) {
        return 0;
    }

    /* Initialize talloc context */
    ctx = talloc_init("fuzzer_json");
    if (!ctx) {
        return 0;
    }

    /* Use first byte to determine split between JSON and jpath */
    split_point = (data[0] * size) / 256;
    if (split_point >= size - 1) {
        split_point = size / 2;
    }

    /* JSON string to parse with json-c */
    if (split_point > 1) {
        json_str = talloc_strndup(ctx, (const char *)(data + 1), split_point - 1);
        if (json_str) {
            /* Parse JSON - exercises json-c library */
            json_obj = json_tokener_parse(json_str);
            if (json_obj) {
                json_object_put(json_obj);
                json_obj = NULL;
            }
        }
    }

    /* jpath expression string to parse with FreeRADIUS */
    if (split_point < size - 1) {
        size_t jpath_len = size - split_point - 1;
        if (jpath_len > 0) {
            jpath_str = talloc_strndup(ctx, 
                                       (const char *)(data + split_point + 1), 
                                       jpath_len);
        }
        
        if (jpath_str) {
            (void)fr_jpath_parse(ctx, &jpath_head, jpath_str, jpath_len);
        }
    }

    talloc_free(ctx);
    return 0;
}
