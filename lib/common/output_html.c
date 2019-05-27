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

typedef struct html_private_s {
    xmlNode *root;
    GQueue *parent_q;
} html_private_t;

static void
html_free_priv(pcmk__output_t *out) {
    html_private_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    xmlFreeNode(priv->root);
    g_queue_free(priv->parent_q);
    free(priv);
}

static bool
html_init(pcmk__output_t *out) {
    html_private_t *priv = NULL;

    /* If html_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(html_private_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->root = create_xml_node(NULL, "html");

    priv->parent_q = g_queue_new();
    g_queue_push_tail(priv->parent_q, priv->root);

    return true;
}

static void
html_reset(pcmk__output_t *out) {
    char *buf = NULL;
    html_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    buf = dump_xml_formatted_with_text(priv->root);
    fprintf(out->dest, "%s", buf);

    free(buf);
    html_free_priv(out);
    html_init(out);
}

static void
html_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    htmlNodePtr node, child_node;
    char *rc_as_str = NULL;
    html_private_t *priv = out->priv;
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
html_info(pcmk__output_t *out, const char *format, ...) {
    /* This function intentially left blank */
}

static void
html_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    htmlNodePtr parent = NULL;
    htmlNodePtr cdata_node = NULL;
    html_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    parent = xmlNewChild(g_queue_peek_tail(priv->parent_q), NULL,
                         (pcmkXmlStr) name, NULL);
    cdata_node = xmlNewCDataBlock(getDocPtr(parent), (pcmkXmlStr) buf, strlen(buf));
    xmlAddChild(parent, cdata_node);
}

static void
html_begin_list(pcmk__output_t *out, const char *name,
               const char *singular_noun, const char *plural_noun) {
    htmlNodePtr list_node = NULL;
    html_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    list_node = create_xml_node(g_queue_peek_tail(priv->parent_q), name);
    g_queue_push_tail(priv->parent_q, list_node);
}

static void
html_list_item(pcmk__output_t *out, const char *name, const char *content) {
    html_private_t *priv = out->priv;
    
    CRM_ASSERT(priv != NULL);

    if (name == NULL) {
        htmlNodePtr node = g_queue_peek_tail(priv->parent_q);
        xmlNodeAddContent(node, (pcmkXmlStr) " ");
        xmlNodeAddContent(node, (pcmkXmlStr) content);
    }
    xmlNewChild(g_queue_peek_tail(priv->parent_q), NULL,
                (pcmkXmlStr) name, (pcmkXmlStr) content);
}

static void
html_end_list(pcmk__output_t *out) {
    html_private_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);
    g_queue_pop_tail(priv->parent_q);
}

static void
html_set_str_prop(pcmk__output_t *out, const char *id, const char *value)
{
    html_private_t *priv = out->priv;
    htmlNodePtr xml_node = g_queue_peek_tail(priv->parent_q);
    if (xml_node->children)
        xml_node = xmlGetLastChild(xml_node);
    xmlSetProp(xml_node, (pcmkXmlStr) id, (pcmkXmlStr) (value ? value : ""));
}

static void
html_set_int_prop(pcmk__output_t *out, const char *id, int value)
{
    char *str = crm_itoa(value);
    html_set_str_prop(out, id, str);
    free(str);
}

static void
html_set_float_prop(pcmk__output_t *out, const char *id, double value)
{
    char *str = crm_ftoa(value);
    html_set_str_prop(out, id, str);
    free(str);
}

static void
html_set_bool_prop(pcmk__output_t *out, const char *id, int condition)
{
    html_set_str_prop(out, id, condition ? "true" : "false");
}

static void
html_finish(pcmk__output_t *out, crm_exit_t exit_status) {
    char *rc_as_str = NULL;
    char *buf = NULL;
    html_private_t *priv = out->priv;

    /* If root is NULL, html_init failed and we are being called from pcmk__output_free
     * in the pcmk__output_new path.
     */
    if (priv->root == NULL) {
        return;
    }

    rc_as_str = crm_itoa(exit_status);

    html_list_item(out, "meta", NULL);
    html_set_str_prop(out, "status", crm_exit_str(exit_status));

    buf = dump_xml_formatted_with_text(priv->root);
    fprintf(out->dest, "%s", buf);

    free(rc_as_str);
    free(buf);
}

pcmk__output_t *
pcmk__mk_html_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = false;

    retval->init = html_init;
    retval->free_priv = html_free_priv;
    retval->finish = html_finish;
    retval->reset = html_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = html_subprocess_output;
    retval->info = html_info;
    retval->output_xml = html_output_xml;

    retval->begin_list = html_begin_list;
    retval->list_item = html_list_item;
    retval->end_list = html_end_list;

    retval->set_str_prop = html_set_str_prop;
    retval->set_int_prop = html_set_int_prop;
    retval->set_float_prop = html_set_float_prop;
    retval->set_bool_prop = html_set_bool_prop;

    return retval;
}
