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

typedef struct text_list_data_s {
    unsigned int len;
    char *singular_noun;
    char *plural_noun;
} text_list_data_t;

typedef struct private_data_s {
    //xmlNode *root;
    GQueue *parent_q;
    //GSList *errors;
} private_data_t;

static void
log_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    g_queue_free(priv->parent_q);
    //g_slist_free(priv->errors);
    free(priv);
}

static bool
log_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    /* If log_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(private_data_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->parent_q = g_queue_new();
    //priv->errors = NULL;

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

static void
log_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    CRM_ASSERT(false); // FIXME! This function is not implemented
}

static void
log_version(pcmk__output_t *out, bool extended) {
    if (extended) {
        fprintf(out->dest, "Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        fprintf(out->dest, "Pacemaker %s\n", PACEMAKER_VERSION);
        fprintf(out->dest, "Written by Andrew Beekhof\n");
    }
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    int len = 0;

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vfprintf(stderr, format, ap);
    CRM_ASSERT(len > 0);
    va_end(ap);

    /* Add a newline. */
    fprintf(stderr, "\n");
}

G_GNUC_PRINTF(2, 3)
static void
log_info(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    int len = 0;

    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vfprintf(out->dest, format, ap);
    CRM_ASSERT(len > 0);
    va_end(ap);

    /* Add a newline. */
    fprintf(out->dest, "\n");
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    pcmk__indented_printf(out, "%s", buf);
}

static void
log_begin_list(pcmk__output_t *out, const char *name,
               const char *singular_noun, const char *plural_noun) {
    private_data_t *priv = out->priv;
    text_list_data_t *new_list = NULL;

    CRM_ASSERT(priv != NULL);

#if FANCY_TEXT_OUTPUT > 0
    pcmk__indented_printf(out, "%s:\n", name);
#endif

    new_list = calloc(1, sizeof(text_list_data_t));
    new_list->len = 0;
    new_list->singular_noun = singular_noun == NULL ? NULL : strdup(singular_noun);
    new_list->plural_noun = plural_noun == NULL ? NULL : strdup(plural_noun);

    g_queue_push_tail(priv->parent_q, new_list);
}

static void
log_list_item(pcmk__output_t *out, const char *name, const char *content) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

#if FANCY_TEXT_OUTPUT > 0
    if (id != NULL) {
        pcmk__indented_printf(out, "* %s: %s\n", id, content);
    } else {
        pcmk__indented_printf(out, "* %s\n", content);
    }
#else
    fprintf(out->dest, "%s\n", content);
#endif

    ((text_list_data_t *) g_queue_peek_tail(priv->parent_q))->len++;
}

static void
log_end_list(pcmk__output_t *out) {
    private_data_t *priv = out->priv;
    text_list_data_t *node = NULL;

    CRM_ASSERT(priv != NULL);
    node = g_queue_pop_tail(priv->parent_q);

    if (node->singular_noun != NULL && node->plural_noun != NULL) {
        if (node->len == 1) {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->singular_noun);
        } else {
            pcmk__indented_printf(out, "%d %s found\n", node->len, node->plural_noun);
        }
    }

    free(node);
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
