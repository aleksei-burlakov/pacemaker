/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/pengine/internal.h>

int
pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...)
{
    xmlNodePtr xml_node = NULL;
    va_list args;

    CRM_ASSERT(tag_name != NULL);

    xml_node = pcmk__output_xml_peek_parent(out);
    CRM_ASSERT(xml_node != NULL);
    xml_node = is_list
        ? create_xml_node(xml_node, tag_name)
        : xmlNewChild(xml_node, NULL, (pcmkXmlStr) tag_name, NULL);

    va_start(args, pairs_count);
    while(pairs_count--) {
        const char *param_name = va_arg(args, const char *);
        const char *param_value = va_arg(args, const char *);
        if (param_name && param_value) {
            xmlSetProp(xml_node, (pcmkXmlStr)param_name, (pcmkXmlStr)param_value);
        }
    };
    va_end(args);

    if (is_list) {
        pcmk__output_xml_push_parent(out, xml_node);
    }
    return 0;
}

static int
pe__ticket_html(pcmk__output_t *out, va_list args) {
    ticket_t *ticket = va_arg(args, ticket_t *);

    if (ticket->last_granted > -1) {
        char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
        out->list_item(out, NULL, "%s:\t%s%s %s", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       time);
        free(time);
    } else {
        out->list_item(out, NULL, "%s:\t%s%s", ticket->id,
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return 0;
}

static int
pe__ticket_text(pcmk__output_t *out, va_list args) {
    ticket_t *ticket = va_arg(args, ticket_t *);

    if (ticket->last_granted > -1) {
        char *time = pcmk_format_named_time("last-granted", ticket->last_granted);
        out->list_item(out, ticket->id, "\t%s%s %s",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "",
                       time);
        free(time);
    } else {
        out->list_item(out, ticket->id, "\t%s%s",
                       ticket->granted ? "granted" : "revoked",
                       ticket->standby ? " [standby]" : "");
    }

    return 0;
}

static int
pe__ticket_xml(pcmk__output_t *out, va_list args) {
    xmlNodePtr node = NULL;

    ticket_t *ticket = va_arg(args, ticket_t *);

    node = pcmk__output_create_xml_node(out, "ticket");
    xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) ticket->id);
    xmlSetProp(node, (pcmkXmlStr) "status", (pcmkXmlStr) (ticket->granted ? "granted" : "revoked"));
    xmlSetProp(node, (pcmkXmlStr) "standby", (pcmkXmlStr) (ticket->standby ? "true" : "false"));

    if (ticket->last_granted > -1) {
        xmlSetProp(node, (pcmkXmlStr) "last-granted",
                   (pcmkXmlStr) crm_now_string(&ticket->last_granted));
    }

    return 0;
}

static int
pe__set_log_level_log(pcmk__output_t *out, va_list args) {
    int log_level = va_arg(args, int);
    pcmk__output_set_log_level(out, log_level);
    return 0;
}

static int
pe__get_log_level_log(pcmk__output_t *out, va_list args) {
    /* It returns not the exit status, but the log_level */
    return pcmk__output_get_log_level(out);
}

static int
pe__set_file_func_line_log(pcmk__output_t *out, va_list args) {
    const char *filename = va_arg(args, char *);
    const char *function = va_arg(args, char *);
    uint32_t lineno = va_arg(args, uint32_t);
    pcmk__output_set_file_func_line(out, filename, function, lineno);
    return 0;
}

// FIXME! Is there a better way to deal w/o pe__list_item_log
static int
pe__print_null_log(pcmk__output_t *out, va_list args) {
    out->list_item(out, NULL, "<NULL>");
    return 0;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "bundle", "xml",  pe__bundle_xml },
    { "bundle", "html",  pe__bundle_html },
    { "bundle", "text",  pe__bundle_text },
    { "bundle", "log",  pe__bundle_text },
    { "clone", "xml",  pe__clone_xml },
    { "clone", "html",  pe__clone_html },
    { "clone", "text",  pe__clone_text },
    { "clone", "log",  pe__clone_text },
    { "group", "xml",  pe__group_xml },
    { "group", "html",  pe__group_html },
    { "group", "text",  pe__group_text },
    { "group", "log",  pe__group_text },
    { "primitive", "xml",  pe__resource_xml },
    { "primitive", "html",  pe__resource_html },
    { "primitive", "text",  pe__resource_text },
    { "primitive", "log",  pe__resource_text },
    { "ticket", "html", pe__ticket_html },
    { "ticket", "text", pe__ticket_text },
    { "ticket", "xml", pe__ticket_xml },
    /* get_log_level, set_log_level, set_file_func_line
     * and print_null are exclusively for the LOG format.
     * Other formats may safely call those messages,
     * there will be no effect. */
    { "get_log_level", "log", pe__get_log_level_log },
    { "set_log_level", "log", pe__set_log_level_log },
    { "set_file_func_line", "log", pe__set_file_func_line_log },
    { "print_null", "log", pe__print_null_log },

    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}

void
pe__output_node(node_t *node, gboolean details, pcmk__output_t *out)
{
    if (node == NULL) {
        crm_trace("<NULL>");
        return;
    }

    CRM_ASSERT(node->details);
    crm_trace("%sNode %s: (weight=%d, fixed=%s)",
              node->details->online ? "" : "Unavailable/Unclean ",
              node->details->uname, node->weight, node->fixed ? "True" : "False");

    if (details) {
        char *pe_mutable = strdup("\t\t");
        GListPtr gIter = node->details->running_rsc;

        crm_trace("\t\t===Node Attributes");
        g_hash_table_foreach(node->details->attrs, print_str_str, pe_mutable);
        free(pe_mutable);

        crm_trace("\t\t=== Resources");

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            pe__output_resource(LOG_TRACE, rsc, FALSE, out);
        }
    }
}

void
pe__output_resource(int log_level, resource_t *rsc, gboolean details, pcmk__output_t  *out)
{
    long options = pe_print_log | pe_print_pending;
    int old_log_level = out->message(out, "get_log_level");

    if (rsc == NULL) {
        out->message(out, "set_log_level", log_level - 1);
        out->message(out, "set_file_func_line", __FILE__, __func__, __LINE__+1);
        /* call list_item for LOG format only */
        out->message(out, "print_null");
        out->message(out, "set_log_level", old_log_level);
        return;
    }
    if (details) {
        options |= pe_print_details;
    }
    out->message(out, "set_log_level", log_level);
    out->message(out, "set_file_func_line", __FILE__, __func__, __LINE__+1);
    out->message(out, crm_element_name(rsc->xml), options, rsc);
    out->message(out, "set_log_level", old_log_level);
}
