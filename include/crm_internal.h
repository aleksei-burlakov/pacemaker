/*
 * Copyright 2006-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_INTERNAL__H
#  define CRM_INTERNAL__H

#  include <config.h>
#  include <portability.h>

#  include <glib.h>
#  include <stdbool.h>
#  include <libxml/tree.h>

#  include <crm/lrmd.h>
#  include <crm/common/logging.h>
#  include <crm/common/ipcs_internal.h>
#  include <crm/common/options_internal.h>
#  include <crm/common/internal.h>

/* This symbol allows us to deprecate public API and prevent internal code from
 * using it while still keeping it for backward compatibility.
 */
#define PCMK__NO_COMPAT

/* Dynamic loading of libraries */
void *find_library_function(void **handle, const char *lib, const char *fn, int fatal);

/* For ACLs */
char *pcmk__uid2username(uid_t uid);
const char *crm_acl_get_set_user(xmlNode * request, const char *field, const char *peer_user);

#  if ENABLE_ACL
#    include <string.h>
static inline gboolean
is_privileged(const char *user)
{
    if (user == NULL) {
        return FALSE;
    } else if (strcmp(user, CRM_DAEMON_USER) == 0) {
        return TRUE;
    } else if (strcmp(user, "root") == 0) {
        return TRUE;
    }
    return FALSE;
}
#  endif

/* char2score */
extern int node_score_red;
extern int node_score_green;
extern int node_score_yellow;

/* Assorted convenience functions */
void crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile);

// printf-style format to create operation ID from resource, action, interval
#define CRM_OP_FMT "%s_%s_%u"

static inline long long
crm_clear_bit(const char *function, int line, const char *target, long long word, long long bit)
{
    long long rc = (word & ~bit);

    if (rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s cleared by %s:%d", bit, target, function, line);
    } else {
        crm_trace("Bit 0x%.8llx cleared by %s:%d", bit, function, line);
    }

    return rc;
}

static inline long long
crm_set_bit(const char *function, int line, const char *target, long long word, long long bit)
{
    long long rc = (word | bit);

    if (rc == word) {
        /* Unchanged */
    } else if (target) {
        crm_trace("Bit 0x%.8llx for %s set by %s:%d", bit, target, function, line);
    } else {
        crm_trace("Bit 0x%.8llx set by %s:%d", bit, function, line);
    }

    return rc;
}

#  define set_bit(word, bit) word = crm_set_bit(__FUNCTION__, __LINE__, NULL, word, bit)
#  define clear_bit(word, bit) word = crm_clear_bit(__FUNCTION__, __LINE__, NULL, word, bit)

char *generate_hash_key(const char *crm_msg_reference, const char *sys);

void strip_text_nodes(xmlNode * xml);
void pcmk_panic(const char *origin);
pid_t pcmk_locate_sbd(void);

#  define crm_config_err(fmt...) { crm_config_error = TRUE; crm_err(fmt); }
#  define crm_config_warn(fmt...) { crm_config_warning = TRUE; crm_warn(fmt); }

#  define F_ATTRD_KEY		"attr_key"
#  define F_ATTRD_ATTRIBUTE	"attr_name"
#  define F_ATTRD_REGEX 	"attr_regex"
#  define F_ATTRD_TASK		"task"
#  define F_ATTRD_VALUE		"attr_value"
#  define F_ATTRD_SET		"attr_set"
#  define F_ATTRD_IS_REMOTE	"attr_is_remote"
#  define F_ATTRD_IS_PRIVATE     "attr_is_private"
#  define F_ATTRD_SECTION	"attr_section"
#  define F_ATTRD_DAMPEN	"attr_dampening"
#  define F_ATTRD_HOST		"attr_host"
#  define F_ATTRD_HOST_ID	"attr_host_id"
#  define F_ATTRD_USER		"attr_user"
#  define F_ATTRD_WRITER	"attr_writer"
#  define F_ATTRD_VERSION	"attr_version"
#  define F_ATTRD_RESOURCE          "attr_resource"
#  define F_ATTRD_OPERATION         "attr_clear_operation"
#  define F_ATTRD_INTERVAL          "attr_clear_interval"
#  define F_ATTRD_IS_FORCE_WRITE "attrd_is_force_write"

/* attrd operations */
#  define ATTRD_OP_ATTR_REMOVE   "attr-remove"
#  define ATTRD_OP_PEER_REMOVE   "peer-remove"
#  define ATTRD_OP_PEER_CLEAR    "peer-clear"
#  define ATTRD_OP_UPDATE        "update"
#  define ATTRD_OP_UPDATE_BOTH   "update-both"
#  define ATTRD_OP_UPDATE_DELAY  "update-delay"
#  define ATTRD_OP_QUERY         "query"
#  define ATTRD_OP_REFRESH       "refresh"
#  define ATTRD_OP_FLUSH         "flush"
#  define ATTRD_OP_SYNC          "sync"
#  define ATTRD_OP_SYNC_RESPONSE "sync-response"
#  define ATTRD_OP_CLEAR_FAILURE "clear-failure"

#  define PCMK__XA_MODE             "mode"

#  define PCMK_ENV_PHYSICAL_HOST "physical_host"


#  if SUPPORT_COROSYNC
#    include <qb/qbipc_common.h>
#    include <corosync/corotypes.h>
typedef struct qb_ipc_request_header cs_ipc_header_request_t;
typedef struct qb_ipc_response_header cs_ipc_header_response_t;
#  else
typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_request_t;

typedef struct {
    int size __attribute__ ((aligned(8)));
    int id __attribute__ ((aligned(8)));
    int error __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8))) cs_ipc_header_response_t;

#  endif

void
attrd_ipc_server_init(qb_ipcs_service_t **ipcs, struct qb_ipcs_service_handlers *cb);
void
stonith_ipc_server_init(qb_ipcs_service_t **ipcs, struct qb_ipcs_service_handlers *cb);

qb_ipcs_service_t *
crmd_ipc_server_init(struct qb_ipcs_service_handlers *cb);

void cib_ipc_servers_init(qb_ipcs_service_t **ipcs_ro,
        qb_ipcs_service_t **ipcs_rw,
        qb_ipcs_service_t **ipcs_shm,
        struct qb_ipcs_service_handlers *ro_cb,
        struct qb_ipcs_service_handlers *rw_cb);

void cib_ipc_servers_destroy(qb_ipcs_service_t *ipcs_ro,
        qb_ipcs_service_t *ipcs_rw,
        qb_ipcs_service_t *ipcs_shm);

static inline void *
realloc_safe(void *ptr, size_t size)
{
    void *new_ptr;

    // realloc(p, 0) can replace free(p) but this wrapper can't
    CRM_ASSERT(size > 0);

    new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        free(ptr);
        abort();
    }
    return new_ptr;
}

const char *crm_xml_add_last_written(xmlNode *xml_node);
void crm_xml_dump(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth);
void crm_buffer_add_char(char **buffer, int *offset, int *max, char c);

bool pcmk__verify_digest(xmlNode *input, const char *expected);

/* IPC Proxy Backend Shared Functions */
typedef struct remote_proxy_s {
    char *node_name;
    char *session_id;

    gboolean is_local;

    crm_ipc_t *ipc;
    mainloop_io_t *source;
    uint32_t last_request_id;
    lrmd_t *lrm;

} remote_proxy_t;

remote_proxy_t *remote_proxy_new(
    lrmd_t *lrmd, struct ipc_client_callbacks *proxy_callbacks,
    const char *node_name, const char *session_id, const char *channel);

int  remote_proxy_check(lrmd_t *lrmd, GHashTable *hash);
void remote_proxy_cb(lrmd_t *lrmd, const char *node_name, xmlNode *msg);
void remote_proxy_ack_shutdown(lrmd_t *lrmd);
void remote_proxy_nack_shutdown(lrmd_t *lrmd);

int  remote_proxy_dispatch(const char *buffer, ssize_t length, gpointer userdata);
void remote_proxy_disconnected(gpointer data);
void remote_proxy_free(gpointer data);

void remote_proxy_relay_event(remote_proxy_t *proxy, xmlNode *msg);
void remote_proxy_relay_response(remote_proxy_t *proxy, xmlNode *msg, int msg_id);

#endif                          /* CRM_INTERNAL__H */
