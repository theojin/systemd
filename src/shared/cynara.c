#ifdef HAVE_CYNARA
#include <cynara-client.h>
#include <cynara-client-async.h>
#include <cynara-creds-commons.h>
#include <cynara-session.h>
#include <pthread.h>
#endif

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "cynara.h"
#include "log.h"

#ifdef HAVE_CYNARA
typedef struct Credentials {
        uid_t uid;
        gid_t gid;
        pid_t pid;
        const char *label;

        bool is_uid_set;
        bool is_gid_set;
        bool is_pid_set;
        bool is_label_set;
} Credentials;

typedef struct EventData {
        sd_event *event;
        sd_event_source *source;
} EventData;

typedef struct AsyncCynaraQuery {
        sd_bus_message *request;
        sd_bus_message_handler_t callback;
        void *userdata;
} AsyncCynaraQuery;

typedef struct CynaraData {
        cynara *cynara_sync;
        pthread_mutex_t *mutex;

        cynara_async *cynara_async;
        EventData *event_data;

        int refcount;
        const char *session;
} CynaraData;

static void change_status(int old_fd, int new_fd, cynara_async_status status, void *userdata);

#define get_cred_decimal(data, result, cred)                            \
        do {                                                            \
                if (!data->is_ ## cred ## _set)                         \
                        return -ENODATA;                                \
                *result = malloc(DECIMAL_STR_WIDTH(data->cred));        \
                if (!*result)                                           \
                        return -ENOMEM;                                 \
                sprintf(*result, "%d", data->cred);                     \
        } while (false)

#define get_cred_string(data, result, cred)                             \
        do {                                                            \
                if (!data->is_ ## cred ## _set)                         \
                        return -ENODATA;                                \
                *result = malloc(strlen(data->cred) + 1);               \
                if (!*result)                                           \
                        return -ENOMEM;                                 \
                sprintf(*result, "%s", data->cred);                     \
        } while (false)

static int cynara_get_client_string(Credentials *c, char **client) {
        int ret;
        enum cynara_client_creds method;

        ret = cynara_creds_get_default_client_method(&method);
        if (ret != CYNARA_API_SUCCESS)
                return ret;

        switch (method) {
                case CLIENT_METHOD_SMACK:
                        get_cred_string(c, client, label);
                        break;
                case CLIENT_METHOD_PID:
                        get_cred_decimal(c, client, pid);
                        break;
                default:
                        return -EINVAL;
        }
        return 0;
}

static int cynara_get_user_string(Credentials *c, char **user) {
        enum cynara_user_creds method;
        int ret;

        ret = cynara_creds_get_default_user_method(&method);
        if (ret != CYNARA_API_SUCCESS)
                return ret;

        switch (method) {
                case USER_METHOD_UID:
                        get_cred_decimal(c, user, uid);
                        break;
                case USER_METHOD_GID:
                        get_cred_decimal(c, user, gid);
                        break;
                default:
                        return -EINVAL;
        }

        return 0;
}

static int init_credentials (sd_bus *bus, const char *name, Credentials *c) {
        sd_bus_creds *creds;
        int ret;

        c->is_uid_set = false;
        c->is_gid_set = false;
        c->is_pid_set = false;
        c->is_label_set = false;

        ret = sd_bus_get_name_creds(bus, name, SD_BUS_CREDS_AUGMENT | SD_BUS_CREDS_PID | SD_BUS_CREDS_UID
                                    | SD_BUS_CREDS_GID | SD_BUS_CREDS_SELINUX_CONTEXT, &creds);
        if (ret < 0)
                return ret;

        ret = sd_bus_creds_get_uid(creds, &c->uid);
        if (ret >= 0)
                c->is_uid_set = true;

        ret = sd_bus_creds_get_gid(creds, &c->gid);
        if (ret >= 0)
                c->is_gid_set = true;

        ret = sd_bus_creds_get_pid(creds, &c->pid);
        if (ret >= 0)
                c->is_pid_set = true;

        ret = sd_bus_creds_get_selinux_context(creds, &c->label);
        if (ret >= 0)
                c->is_label_set = true;

        sd_bus_creds_unref(creds);
        return 0;
}
#endif

int cynara_data_new(sd_event *event, CynaraData **cynara_data) {
#ifdef HAVE_CYNARA
        int r;
        CynaraData *data;

        data = new0(CynaraData, 1);
        if (!data)
                return -ENOMEM;

        r = pthread_mutex_init(data->mutex, NULL);
        if (r < 0)
                goto error;

        data->event_data = new0(EventData, 1);
        if (!data->event_data) {
                goto error;
                r = -ENOMEM;
        }

        data->event_data->event = event;

        r = cynara_initialize(&data->cynara_sync, NULL);
        if (r != CYNARA_API_SUCCESS)
                goto error;

        r = cynara_async_initialize(&data->cynara_async, NULL, change_status, data->event_data);
        if (r != CYNARA_API_SUCCESS)
                goto error;

        data->session = cynara_session_from_pid(getpid());

        *cynara_data = data;
        return 0;

error:
        cynara_data_free(data);
        return r;
#else
        return 0;
#endif
}

void cynara_data_free(CynaraData *data) {
#ifdef HAVE_CYNARA
        cynara_finish(data->cynara_sync);
        cynara_async_finish(data->cynara_async);

        pthread_mutex_destroy(data->mutex);
        sd_event_source_unref(data->event_data->source);
        free(data->event_data);
        free(data->session);
        free(data);
#endif
}

int bus_verify_cynara(sd_bus_message *call, CynaraData *cynara_data) {
#ifdef HAVE_CYNARA
        int ret, cynara_ret;
        char *user, *client;
        Credentials sender_creds;
        char *privilege = "http://tizen.org/privilege/internal/systemd/control.unit";

        assert(cynara_data);
        assert(call);

        ret = init_credentials(call->bus, call->sender, &sender_creds);
        if (ret < 0)
                return -EACCES;

        ret = cynara_get_user_string(&sender_creds, &user);
        if (ret < 0)
                return -EACCES;

        ret = cynara_get_client_string(&sender_creds, &client);
        if (ret < 0)
                return -EACCES;

        pthread_mutex_lock(cynara_data->mutex);

        cynara_ret = cynara_check(cynara_data->cynara_sync, client, cynara_data->session, user, privilege);
        if (cynara_ret == CYNARA_API_ACCESS_ALLOWED)
                ret = 1;
        else
                ret = -EACCES;

        pthread_mutex_unlock(cynara_data->mutex);
        return ret;
#else
        return -EACCES;
#endif
}

#ifdef HAVE_CYNARA
static int cynara_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        int r;
        CynaraData *data = (CynaraData *)userdata;

        r = cynara_async_process(data->cynara_async);

        return r;
}

static void change_status(int old_fd, int new_fd, cynara_async_status status, void *userdata) {
        EventData *event_data = (EventData *)userdata;

        uint32_t events_mask = EPOLLIN;
        if (status == CYNARA_STATUS_FOR_RW)
                events_mask |= EPOLLOUT;

        if (old_fd == -1) {
                sd_event_add_io(event_data->event, &event_data->source, new_fd, events_mask, cynara_event_handler, event_data);
        }
        else if (new_fd != -1) {
                sd_event_source_set_io_fd(event_data->source, new_fd);
        }
        else {
                sd_event_source_unref(event_data->source);
                free(event_data);
        }
}


static void async_cynara_query_free(AsyncCynaraQuery *q) {
        if (!q)
                return;
        sd_bus_message_unref(q->request);
        free(q);
}

static void process_cynara_response(cynara_check_id check_id, cynara_async_call_cause cause, int response, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        AsyncCynaraQuery *q = (AsyncCynaraQuery *)userdata;
        int r;

        if (cause == CYNARA_CALL_CAUSE_ANSWER) {
                r = sd_bus_message_rewind(q->request, true);
                if (r < 0) {
                        r = sd_bus_reply_method_errno(q->request, r, NULL);
                        goto finish;
                }

                r = q->callback(q->request, q->userdata, &error_buffer);
                r = bus_maybe_reply_error(q->request, r, &error_buffer);
        }
finish:
        async_cynara_query_free(q);
}

static int check_privilege(sd_bus_message *call, CynaraData *cynara_data, int capability, const char *client, const char *user, const char *privilege) {
        AsyncCynaraQuery *q;
        sd_bus_message_handler_t callback;
        void *userdata;
        int ret;

        ret = sd_bus_query_sender_privilege(call, capability);
        if (ret < 0)
                return ret;
        else if (ret > 0)
                return 1;

        if (sd_bus_get_current_message(call->bus) != call)
                return -EINVAL;

        callback = sd_bus_get_current_handler(call->bus);
        if (!callback)
                return -EINVAL;

        userdata = sd_bus_get_current_userdata(call->bus);

        q = new0(AsyncCynaraQuery, 1);
        if (!q)
                return -ENOMEM;

        q->request = sd_bus_message_ref(call);
        q->callback = callback;
        q->userdata = userdata;

        ret = cynara_async_create_request(cynara_data->cynara_async, client, cynara_data->session, user, privilege, NULL, process_cynara_response, q);
        if(ret != CYNARA_API_SUCCESS) {
                async_cynara_query_free(q);
                return -EACCES;
        }
        return 0;
}
#endif

int bus_verify_cynara_async(sd_bus_message *call, int capability, CynaraData *cynara_data) {
#ifdef HAVE_CYNARA
        int ret;
        Credentials *c;
        char *user, *client;
        char *privilege = "http://tizen.org/privilege/internal/systemd/control.unit";

        assert(cynara_data);
        assert(call);

        ret = init_credentials(call->bus, call->sender, c);
        if (ret < 0)
                return ret;

        ret = cynara_get_client_string(c, &client);
        if (ret < 0)
                return ret;

        ret = cynara_get_user_string(c, &user);
        if (ret < 0)
                return ret;

        ret = cynara_async_check_cache(cynara_data->cynara_async, client, cynara_data->session, user, privilege);
        switch(ret) {
                case CYNARA_API_ACCESS_ALLOWED:
                        return 1;
                case CYNARA_API_ACCESS_DENIED:
                        return -EACCES;
                case CYNARA_API_CACHE_MISS:
                        return check_privilege(call, cynara_data, capability, client, user, privilege);
                default:
                        return -EACCES;
        }
#else
        return -EACCES;
#endif
}
