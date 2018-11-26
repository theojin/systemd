#include <stdbool.h>
#include <sys/types.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "hashmap.h"
#include "polkit.h"
#include "strv.h"

int bus_test_polkit(
                sd_bus_message *call,
                const char *action,
                const char **details,
                bool *_challenge,
                sd_bus_error *e) {

#ifdef ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *request = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int authorized = false, challenge = false;
        const char *sender, **k, **v;
        int r;

        sender = sd_bus_message_get_sender(call);
        if (!sender)
                return -EBADMSG;

        r = sd_bus_message_new_method_call(
                        call->bus,
                        &request,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        request,
                        "(sa{sv})s",
                        "system-bus-name", 1, "name", "s", sender,
                        action);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(request, 'a', "{ss}");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(k, v, details) {
                r = sd_bus_message_append(request, "{ss}", *k, *v);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(request);
        if (r < 0)
                return r;

        r = sd_bus_message_append(request, "us", 0, NULL);
        if (r < 0)
                return r;

        r = sd_bus_call(call->bus, request, 0, e, &reply);
        if (r < 0) {
                /* Treat no PK available as access denied */
                if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN)) {
                        sd_bus_error_free(e);
                        return -EACCES;
                }

                return r;
        }

        r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "bb", &authorized, &challenge);
        if (r < 0)
                return r;

        if (authorized)
                return 1;

        if (_challenge) {
                *_challenge = challenge;
                return 0;
        }

        return -EACCES;
#else
        return -EACCES;
#endif
}

#ifdef ENABLE_POLKIT

typedef struct AsyncPrivilegeQuery {
        sd_bus_message *request, *reply;
        sd_bus_message_handler_t callback;
        void *userdata;
        sd_bus_slot *slot;
        Hashmap *registry;
} AsyncPrivilegeQuery;

static void async_privilege_query_free(AsyncPrivilegeQuery *q) {
        if (!q)
                return;

        sd_bus_slot_unref(q->slot);

        if (q->registry && q->request)
                hashmap_remove(q->registry, q->request);

        sd_bus_message_unref(q->request);
        sd_bus_message_unref(q->reply);

        free(q);
}

static int async_polkit_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        AsyncPrivilegeQuery *q = userdata;
        int r;

        assert(reply);
        assert(q);

        q->slot = sd_bus_slot_unref(q->slot);
        q->reply = sd_bus_message_ref(reply);

        r = sd_bus_message_rewind(q->request, true);
        if (r < 0) {
                r = sd_bus_reply_method_errno(q->request, r, NULL);
                goto finish;
        }

        r = q->callback(q->request, q->userdata, &error_buffer);
        r = bus_maybe_reply_error(q->request, r, &error_buffer);

finish:
        async_privilege_query_free(q);
        return r;
}

#endif

void polkit_registry_free (Hashmap *polkit_registry) {
#ifdef ENABLE_POLKIT
        AsyncPrivilegeQuery *q;
        while ((q = hashmap_steal_first(polkit_registry)))
                    async_privilege_query_free(q);

        hashmap_free(polkit_registry);
#endif
}

int bus_verify_polkit_async(
                sd_bus_message *call,
                int capability,
                const char *action,
                const char **details,
                bool interactive,
                uid_t good_user,
                Hashmap **registry,
                sd_bus_error *error) {

#ifdef ENABLE_POLKIT
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        AsyncPrivilegeQuery *q;
        const char *sender, **k, **v;
        sd_bus_message_handler_t callback;
        void *userdata;
        int c;
#endif
        int r;

#ifdef ENABLE_POLKIT
        q = hashmap_get(*registry, call);
        if (q) {
                int authorized, challenge;

                /* This is the second invocation of this function, and
                 * there's already a response from polkit, let's
                 * process it */
                assert(q->reply);

                if (sd_bus_message_is_method_error(q->reply, NULL)) {
                        const sd_bus_error *e;

                        /* Copy error from polkit reply */
                        e = sd_bus_message_get_error(q->reply);
                        sd_bus_error_copy(error, e);

                        /* Treat no PK available as access denied */
                        if (sd_bus_error_has_name(e, SD_BUS_ERROR_SERVICE_UNKNOWN))
                                return -EACCES;

                        return -sd_bus_error_get_errno(e);
                }

                r = sd_bus_message_enter_container(q->reply, 'r', "bba{ss}");
                if (r >= 0)
                        r = sd_bus_message_read(q->reply, "bb", &authorized, &challenge);

                if (r < 0)
                        return r;

                if (authorized)
                        return 1;

                if (challenge)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED, "Interactive authentication required.");

                return -EACCES;
        }
#endif

        r = sd_bus_query_sender_privilege(call, capability);
        if (r < 0)
                return r;
        else if (r > 0)
                return 1;

#ifdef ENABLE_POLKIT
        if (sd_bus_get_current_message(call->bus) != call)
                return -EINVAL;

        callback = sd_bus_get_current_handler(call->bus);
        if (!callback)
                return -EINVAL;

        userdata = sd_bus_get_current_userdata(call->bus);

        sender = sd_bus_message_get_sender(call);
        if (!sender)
                return -EBADMSG;

        c = sd_bus_message_get_allow_interactive_authorization(call);
        if (c < 0)
                return c;
        if (c > 0)
                interactive = true;

        r = hashmap_ensure_allocated(registry, NULL);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(
                        call->bus,
                        &pk,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "CheckAuthorization");
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        pk,
                        "(sa{sv})s",
                        "system-bus-name", 1, "name", "s", sender,
                        action);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(pk, 'a', "{ss}");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(k, v, details) {
                r = sd_bus_message_append(pk, "{ss}", *k, *v);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(pk);
        if (r < 0)
                return r;

        r = sd_bus_message_append(pk, "us", !!interactive, NULL);
        if (r < 0)
                return r;

        q = new0(AsyncPrivilegeQuery, 1);
        if (!q)
                return -ENOMEM;

        q->request = sd_bus_message_ref(call);
        q->callback = callback;
        q->userdata = userdata;

        r = hashmap_put(*registry, call, q);
        if (r < 0) {
                async_privilege_query_free(q);
                return r;
        }

        q->registry = *registry;

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0) {
                async_privilege_query_free(q);
                return r;
        }

        return 0;
#endif

        return -EACCES;
}
