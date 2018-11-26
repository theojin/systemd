#pragma once

#include "sd-bus.h"

#include "hashmap.h"

typedef struct AsyncPrivilegeQuery AsyncPrivilegeQuery;

void polkit_registry_free (Hashmap *polkit_registry);

int bus_test_polkit(sd_bus_message *call, const char *action, const char **details, bool *_challenge, sd_bus_error *e);
int bus_verify_polkit_async(sd_bus_message *call, int capability, const char *action, const char **details, bool interactive, uid_t good_user, Hashmap **registry, sd_bus_error *error);