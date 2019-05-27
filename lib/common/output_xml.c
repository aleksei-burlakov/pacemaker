/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/output.h>
#include <crm/common/xml.h>

typedef struct xml_private_s {
    xmlNode *root;
    GQueue *parent_q;
} xml_private_t;

static void
xml_free_priv(pcmk__output_t *out) {
    xml_private_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    xmlFreeNode(priv->root);
    g_queue_free(priv->parent_q);
    free(priv);
}

static bool
xml_init(pcmk__output_t *out) {
    xml_private_t *priv = NULL;

    /* If xml_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(xml_private_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->root = create_xml_node(NULL, "pacemaker-result");
    xmlSetProp(priv->root, (pcmkXmlStr) "api-version", (pcmkXmlStr) PCMK__API_VERSION);

    if (out->request != NULL) {
        xmlSetProp(priv->root, (pcmkXmlStr) "request", (pcmkXmlStr) out->request);
    }

    priv->parent_q = g_queue_new();
    g_queue_push_tail(priv->parent_q, priv->root);

    return true;
}

static void
xml_finish(pcmk__output_t *out, crm_exit_t exit_status) {
    xmlNodePtr node;
    char *rc_as_str = NULL;
    char *buf = NULL;
    xml_private_t *priv = out->priv;

    /* If root is NULL, xml_init failed and we are being called from pcmk__output_free
     * in the pcmk__output_new path.
     */
    if (priv->root == NULL) {
        return;
    }

    rc_as_str = crm_itoa(exit_status);

    node = xmlNewTextChild(priv->root, NULL, (pcmkXmlStr) "status",
                           (pcmkXmlStr) crm_exit_str(exit_status));
    xmlSetProp(node, (pcmkXmlStr) "code", (pcmkXmlStr) rc_as_str);

    buf = dump_xml_formatted_with_text(priv->root);
    fprintf(out->dest, "%s", buf);

    free(rc_as_str);
    free(buf);
}

static void
xml_reset(pcmk__output_t *out) {
    char *buf = NULL;
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    buf = dump_xml_formatted_with_text(priv->root);
    fprintf(out->dest, "%s", buf);

    free(buf);
    xml_free_priv(out);
    xml_init(out);
}

static void
xml_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    xmlNodePtr node, child_node;
    char *rc_as_str = NULL;
    xml_private_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    rc_as_str = crm_itoa(exit_status);

    node = xmlNewNode(g_queue_peek_tail(priv->parent_q), (pcmkXmlStr) "command");
    xmlSetProp(node, (pcmkXmlStr) "code", (pcmkXmlStr) rc_as_str);

    if (proc_stdout != NULL) {
        child_node = xmlNewTextChild(node, NULL, (pcmkXmlStr) "output",
                                     (pcmkXmlStr) proc_stdout);
        xmlSetProp(child_node, (pcmkXmlStr) "source", (pcmkXmlStr) "stdout");
    }

    if (proc_stderr != NULL) {
        child_node = xmlNewTextChild(node, NULL, (pcmkXmlStr) "output",
                                     (pcmkXmlStr) proc_stderr);
        xmlSetProp(node, (pcmkXmlStr) "source", (pcmkXmlStr) "stderr");
    }

    pcmk__xml_add_node(out, node);
    free(rc_as_str);
}

G_GNUC_PRINTF(2, 3)
static void
xml_info(pcmk__output_t *out, const char *format, ...) {
    /* This function intentially left blank */
}

static void
xml_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    xmlNodePtr parent = NULL;
    xmlNodePtr cdata_node = NULL;
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    parent = xmlNewChild(g_queue_peek_tail(priv->parent_q), NULL,
                         (pcmkXmlStr) name, NULL);
    cdata_node = xmlNewCDataBlock(getDocPtr(parent), (pcmkXmlStr) buf, strlen(buf));
    xmlAddChild(parent, cdata_node);
}

static void
xml_begin_list(pcmk__output_t *out, const char *name,
               const char *singular_noun, const char *plural_noun) {
    xmlNodePtr list_node = NULL;
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    list_node = create_xml_node(g_queue_peek_tail(priv->parent_q), "list");
    xmlSetProp(list_node, (pcmkXmlStr) "name", (pcmkXmlStr) name);
    g_queue_push_tail(priv->parent_q, list_node);
}

static void
xml_list_item(pcmk__output_t *out, const char *name, const char *content) {
    xml_private_t *priv = out->priv;
    xmlNodePtr item_node = NULL;

    CRM_ASSERT(priv != NULL);

    item_node = xmlNewChild(g_queue_peek_tail(priv->parent_q), NULL,
                            (pcmkXmlStr) "item", (pcmkXmlStr) content);
    xmlSetProp(item_node, (pcmkXmlStr) "name", (pcmkXmlStr) name);
}

static void
xml_end_list(pcmk__output_t *out) {
    char *buf = NULL;
    xml_private_t *priv = out->priv;
    xmlNodePtr node;

    CRM_ASSERT(priv != NULL);

    node = g_queue_pop_tail(priv->parent_q);
    buf = crm_strdup_printf("%lu", xmlChildElementCount(node));
    xmlSetProp(node, (pcmkXmlStr) "count", (pcmkXmlStr) buf);
    free(buf);
}

static void
xml_set_str_prop(pcmk__output_t *out, const char *id, const char *value)
{
    xml_private_t *priv = out->priv;
    xmlNodePtr xml_node = g_queue_peek_tail(priv->parent_q);
    if (xml_node->children)
        xml_node = xmlGetLastChild(xml_node);
    xmlSetProp(xml_node, (pcmkXmlStr) id, (pcmkXmlStr) (value ? value : ""));
}

static void
xml_set_int_prop(pcmk__output_t *out, const char *id, int value)
{
    char *str = crm_itoa(value);
    xml_set_str_prop(out, id, str);
    free(str);
}

static void
xml_set_float_prop(pcmk__output_t *out, const char *id, double value)
{
    char *str = crm_ftoa(value);
    xml_set_str_prop(out, id, str);
    free(str);
}

static void
xml_set_bool_prop(pcmk__output_t *out, const char *id, int condition)
{
    xml_set_str_prop(out, id, condition ? "true" : "false");
}

pcmk__output_t *
pcmk__mk_xml_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = false;

    retval->init = xml_init;
    retval->free_priv = xml_free_priv;
    retval->finish = xml_finish;
    retval->reset = xml_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = xml_subprocess_output;
    retval->info = xml_info;
    retval->output_xml = xml_output_xml;

    retval->begin_list = xml_begin_list;
    retval->list_item = xml_list_item;
    retval->end_list = xml_end_list;

    retval->set_str_prop = xml_set_str_prop;
    retval->set_int_prop = xml_set_int_prop;
    retval->set_float_prop = xml_set_float_prop;
    retval->set_bool_prop = xml_set_bool_prop;

    return retval;
}

void
pcmk__xml_add_node(pcmk__output_t *out, xmlNodePtr node) {
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    CRM_ASSERT(node != NULL);

    xmlAddChild(g_queue_peek_tail(priv->parent_q), node);
}

void
pcmk__xml_push_parent(pcmk__output_t *out, xmlNodePtr parent) {
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    CRM_ASSERT(parent != NULL);

    g_queue_push_tail(priv->parent_q, parent);
}

void
pcmk__xml_pop_parent(pcmk__output_t *out) {
    xml_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    CRM_ASSERT(g_queue_get_length(priv->parent_q) > 0);

    g_queue_pop_tail(priv->parent_q);
}
