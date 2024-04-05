 /*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static void
target_is_NULL(void **state)
{
    xmlNode *test_xml_1 = pcmk__xe_create(NULL, "test_xml_1");
    xmlNode *test_xml_2 = NULL;

    pcmk__xe_set_props(test_xml_1, "test_prop", "test_value", NULL);

    pcmk__xe_copy_attrs(test_xml_2, test_xml_1, pcmk__xaf_none);

    assert_ptr_equal(test_xml_2, NULL);
}

static void
src_is_NULL(void **state)
{
    xmlNode *test_xml_1 = NULL;
    xmlNode *test_xml_2 = pcmk__xe_create(NULL, "test_xml_2");

    pcmk__xe_copy_attrs(test_xml_2, test_xml_1, pcmk__xaf_none);

    assert_ptr_equal(test_xml_2->properties, NULL);
}

static void
copying_is_successful(void **state)
{
    const char *xml_1_value;
    const char *xml_2_value;

    xmlNode *test_xml_1 = pcmk__xe_create(NULL, "test_xml_1");
    xmlNode *test_xml_2 = pcmk__xe_create(NULL, "test_xml_2");

    pcmk__xe_set_props(test_xml_1, "test_prop", "test_value", NULL);

    pcmk__xe_copy_attrs(test_xml_2, test_xml_1, pcmk__xaf_none);

    xml_1_value = crm_element_value(test_xml_1, "test_prop");
    xml_2_value = crm_element_value(test_xml_2, "test_prop");

    assert_string_equal(xml_1_value, xml_2_value);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(target_is_NULL),
                cmocka_unit_test(src_is_NULL),
                cmocka_unit_test(copying_is_successful))
