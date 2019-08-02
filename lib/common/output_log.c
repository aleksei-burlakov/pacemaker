/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <ctype.h>
#include <libxml/HTMLtree.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/output.h>
#include <crm/common/xml.h>

GOptionEntry pcmk__log_output_entries[] = {
    { NULL }
};

typedef struct private_log_message_s {
    uint8_t log_level; /* the log level of the message */
    char filename[LINE_MAX];
    char function[LINE_MAX];
    uint32_t lineno;
    char text[LINE_MAX];
} private_log_message_t;

typedef struct private_data_s {
    int log_level; /* current log level */
    GQueue *messages; /* queue of private_log_message_t */
    GList *prefixes; /* string prefixes taken in the log_begin_list */
} private_data_t;

static void
log_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    g_queue_free(priv->messages);
    free(priv);
}

static bool
log_init(pcmk__output_t *out) {

    /* If log_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    }

    out->priv = calloc(1, sizeof(private_data_t));
    if (out->priv == NULL) {
         return false;
     }

    pcmk__output_set_log_level(out, LOG_INFO);
    ((private_data_t *)out->priv)->messages = g_queue_new();
    return true;
}

static void
log_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    /* This function intentionally left blank */
}

static void
log_reset(pcmk__output_t *out) {
    CRM_ASSERT(out->priv != NULL);

    log_free_priv(out);
    log_init(out);
}

static void log_output_message(gpointer item) {
    private_log_message_t *message = (private_log_message_t *)item;
    qb_log_from_external_source(message->function, message->filename, "%s",
                                message->log_level, message->lineno, 0 , message->text);
}

static void log_subprocess_output(pcmk__output_t *out, int exit_status,
                                  const char *proc_stdout, const char *proc_stderr) {
    g_queue_foreach(((private_data_t *)out->priv)->messages, (GFunc)log_output_message, NULL);
}

static void
log_version(pcmk__output_t *out, bool extended) {
    if (extended) {
        /* FIXME! __FILE__, __func__ and __LINE__ will get the wrong values.
         * One would expect those from up the call stack */
        pcmk__output_do_crm_log(out, "Pacemaker %s (Build: %s): %s\n",
                   PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        pcmk__output_do_crm_log(out, "Pacemaker %s\n", PACEMAKER_VERSION);
        pcmk__output_do_crm_log(out, "Written by Andrew Beekhof\n");
    }
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    //int offset = 0;
    //char buffer[LINE_MAX];

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    //offset += vsnprintf(buffer + offset, LINE_MAX - offset, format, ap); /* FIXME! clang compilation error. */
    va_end(ap);

    // crm_err(((const char *)buffer)); /* FIXME! compilation error. */
}

G_GNUC_PRINTF(2, 3)
static void
log_info(pcmk__output_t *out, const char *format, ...) {
    /* This function intentially left blank */
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    private_data_t *priv = out->priv;
    xmlNodePtr node = NULL;

    CRM_ASSERT(priv != NULL);

    node = create_xml_node(NULL, name);
    xmlNodeSetContent(node, (pcmkXmlStr) buf);
    do_crm_log_xml(pcmk__output_get_log_level(out), name, node);
    free(node);
}

static void
log_begin_list(pcmk__output_t *out, const char *name,
               const char *singular_noun, const char *plural_noun) {
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);
    priv->prefixes = g_list_append(priv->prefixes, crm_strdup_printf("%s", name));
}

static void
log_list_item(pcmk__output_t *out, const char *name, const char *content) {
    private_data_t *priv = out->priv;
    const char *priority = NULL;
    char prefix[LINE_MAX];
    int offset = 0;

    CRM_ASSERT(priv != NULL);

    priority = crm_int2priority(pcmk__output_get_log_level(out));
    CRM_ASSERT(priority != NULL);

    for (GList* gIter = priv->prefixes; gIter; gIter = gIter->next) {
        offset += snprintf(prefix + offset, LINE_MAX - offset, "%s: %s", prefix, (char *)gIter->data);
    }

    if (name != NULL) {
        /* FIXME! __FILE__, __func__ and __LINE__ will get the wrong values.
         * One would expect those from up the call stack */
        pcmk__output_do_crm_log(out, "%s: %s: %s: %s", priority, prefix, name, content);
    } else {
        pcmk__output_do_crm_log(out, "%s: %s: %s", priority, prefix, content);
    }
}

static void
log_end_list(pcmk__output_t *out) {

    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    free((char *)g_list_last(priv->prefixes)->data);
    free(g_list_last(priv->prefixes));
}

pcmk__output_t *
pcmk__mk_log_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "log";
    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = false;

    retval->init = log_init;
    retval->free_priv = log_free_priv;
    retval->finish = log_finish;
    retval->reset = log_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = log_subprocess_output;
    retval->version = log_version;
    retval->info = log_info;
    retval->err = log_err;
    retval->output_xml = log_output_xml;

    retval->begin_list = log_begin_list;
    retval->list_item = log_list_item;
    retval->end_list = log_end_list;

    return retval;
}

int pcmk__output_get_log_level(pcmk__output_t *out) {
    CRM_ASSERT(out && out->priv);
    return ((private_data_t *)out->priv)->log_level;
}

void pcmk__output_set_log_level(pcmk__output_t *out, int log_level) {
    CRM_ASSERT(out && out->priv);
    ((private_data_t *)out->priv)->log_level = log_level;
}

void pcmk__output_crm_log(pcmk__output_t *out, const char *function, const char *filename,
                          const char *format, uint32_t lineno, ...) {
    va_list ap;
    private_log_message_t *message = calloc(1, sizeof(private_log_message_t));
    CRM_ASSERT(message != NULL);

    message->log_level = pcmk__output_get_log_level(out);
    snprintf(message->filename, LINE_MAX, "%s", filename);
    snprintf(message->function, LINE_MAX, "%s", function);
    message->lineno = lineno;

    va_start(ap, lineno);
    // vsnprintf(message->text, LINE_MAX, format, ap); /* FIXME! clang compilation error. */
    va_end(ap);

    /* save the message for the future use */
    g_queue_push_tail(((private_data_t *)out->priv)->messages, message);
    /* print it now */
    log_output_message(message);
}
