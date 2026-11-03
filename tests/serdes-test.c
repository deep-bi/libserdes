/**
 * Copyright 2025 Deep.BI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <curl/curl.h>
#include "test-macros.h"
#include "serdes_int.h"

static void unittest_setting_client_cert (void)
{
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0, NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));
    const char* key_password = NULL;

    serdes_err_t err = serdes_conf_set_client_cert(sconf,
                                                   "ca_location",
                                                   "certificate_location",
                                                   "key_location",
                                                   key_password,
                                                   err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(err == SERDES_ERR_OK);
    assert(!strcmp(sconf->tls_conf.client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.key_location, "key_location"));
    assert(sconf->tls_conf.client_cert.key_password == NULL);

    serdes_conf_destroy(sconf);
}

static void unittest_attempt_to_set_client_cert_with_null_conf (void)
{
    serdes_conf_t *sconf = NULL;

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));
    const char* key_password = NULL;

    serdes_err_t err = serdes_conf_set_client_cert(sconf,
                                                   "ca_location",
                                                   "certificate_location",
                                                   "key_location",
                                                   key_password,
                                                   err_buf, sizeof(err_buf));

    assert(err_buf[0] != '\0');
    assert(err == SERDES_ERR_NULL_PARAM);
    assert(sconf == NULL);
}

static void unittest_setting_client_certificate_twice (void)
{
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0, NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));
    const char* dummy_string = "dummy_string";

    serdes_err_t err = serdes_conf_set_client_cert(sconf,
                                                   dummy_string,
                                                   dummy_string,
                                                   dummy_string,
                                                   dummy_string,
                                                   err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(err == SERDES_ERR_OK);

    err = serdes_conf_set_client_cert(sconf,
                                      "ca_location",
                                      "certificate_location",
                                      "key_location",
                                      "key_password",
                                      err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(err == SERDES_ERR_OK);
    assert(!strcmp(sconf->tls_conf.client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.key_location, "key_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.key_password, "key_password"));

    serdes_conf_destroy(sconf);
}

static void unittest_serdes_conf_deep_copy (void) {
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0, NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));
    const char* key_password = NULL;

    serdes_conf_set_client_cert(sconf,
                          "ca_location",
                          "certificate_location",
                          "key_location",
                          key_password,
                          err_buf, sizeof(err_buf));

    serdes_conf_t *sconf_copy = serdes_conf_copy(sconf);
    assert(!strcmp(sconf_copy->tls_conf.client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf_copy->tls_conf.client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf_copy->tls_conf.client_cert.key_location, "key_location"));
    assert(sconf_copy->tls_conf.client_cert.key_password == NULL);

    assert(sconf_copy->tls_conf.client_cert.ca_location != sconf->tls_conf.client_cert.ca_location);
    assert(sconf_copy->tls_conf.client_cert.certificate_location != sconf->tls_conf.client_cert.certificate_location);
    assert(sconf_copy->tls_conf.client_cert.key_location != sconf->tls_conf.client_cert.key_location);
    assert(sconf_copy->tls_conf.client_cert.key_password == sconf->tls_conf.client_cert.key_password);

    serdes_conf_destroy(sconf);
    serdes_conf_destroy(sconf_copy);
}

static void unittest_setting_min_tls_version (void) {
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0, NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));

    const char* min_tls_version_key = "schema.registry.ssl.tls.min.version";
    const char* min_tls_version_value = "1.1";
    const int expected_min_tls_version = CURL_SSLVERSION_TLSv1_1;

    serdes_err_t err = serdes_conf_set(sconf,
                                       min_tls_version_key,
                                       min_tls_version_value,
                                       err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(err == SERDES_ERR_OK);
    assert(sconf->tls_conf.tls_min_version == expected_min_tls_version);
    serdes_conf_destroy(sconf);
}

static void unittest_setting_incorrect_min_tls_version (void) {
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0, NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));

    const char* min_tls_version_key = "schema.registry.ssl.tls.min.version";
    const char* min_tls_version_value = "dummy";

    serdes_err_t err = serdes_conf_set(sconf,
                                       min_tls_version_key,
                                       min_tls_version_value,
                                       err_buf, sizeof(err_buf));

    assert(err_buf[0] != '\0');
    assert(err == SERDES_ERR_CONF_INVALID);
    serdes_conf_destroy(sconf);
}

static void unittest_attempt_to_set_client_cert_with_null_errstr (void)
{
    /* Must not write to the NULL errstr despite the non-zero size */
    serdes_err_t err = serdes_conf_set_client_cert(NULL,
                                                   "ca_location",
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   NULL, 512);

    assert(err == SERDES_ERR_NULL_PARAM);
}

static void unittest_setting_client_cert_via_conf_properties (void)
{
    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));

    serdes_conf_t *sconf = serdes_conf_new(err_buf, sizeof(err_buf),
                                           "schema.registry.ssl.ca.location",
                                           "ca_location",
                                           "schema.registry.ssl.certificate.location",
                                           "certificate_location",
                                           "schema.registry.ssl.key.location",
                                           "key_location",
                                           "schema.registry.ssl.key.password",
                                           "key_password",
                                           NULL);

    assert(sconf != NULL);
    assert(err_buf[0] == '\0');
    assert(!strcmp(sconf->tls_conf.client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.key_location, "key_location"));
    assert(!strcmp(sconf->tls_conf.client_cert.key_password, "key_password"));

    serdes_conf_destroy(sconf);
}

static void unittest_unsetting_client_cert_property (void)
{
    serdes_conf_t *sconf = serdes_conf_new(NULL, 0,
                                           "schema.registry.ssl.ca.location",
                                           "ca_location",
                                           "schema.registry.ssl.key.password",
                                           "key_password",
                                           NULL);

    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));

    serdes_err_t err = serdes_conf_set(sconf,
                                       "schema.registry.ssl.key.password",
                                       "",
                                       err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(err == SERDES_ERR_OK);
    assert(sconf->tls_conf.client_cert.key_password == NULL);
    assert(!strcmp(sconf->tls_conf.client_cert.ca_location, "ca_location"));

    serdes_conf_destroy(sconf);
}

static void unittest_serdes_new_keeps_tls_conf (void)
{
    char err_buf[512];
    memset(err_buf, 0, sizeof(err_buf));

    serdes_conf_t *sconf = serdes_conf_new(err_buf, sizeof(err_buf),
                                           "schema.registry.url",
                                           "https://localhost:8081",
                                           "schema.registry.ssl.ca.location",
                                           "ca_location",
                                           "schema.registry.ssl.certificate.location",
                                           "certificate_location",
                                           "schema.registry.ssl.key.location",
                                           "key_location",
                                           "schema.registry.ssl.key.password",
                                           "key_password",
                                           "schema.registry.ssl.tls.min.version",
                                           "1.2",
                                           NULL);
    assert(sconf != NULL);

    /* serdes_new() takes ownership of sconf */
    serdes_t *sd = serdes_new(sconf, err_buf, sizeof(err_buf));

    assert(sd != NULL);
    assert(!strcmp(sd->sd_conf.tls_conf.client_cert.ca_location, "ca_location"));
    assert(!strcmp(sd->sd_conf.tls_conf.client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sd->sd_conf.tls_conf.client_cert.key_location, "key_location"));
    assert(!strcmp(sd->sd_conf.tls_conf.client_cert.key_password, "key_password"));
    assert(sd->sd_conf.tls_conf.tls_min_version == CURL_SSLVERSION_TLSv1_2);

    serdes_destroy(sd);
}

void register_serdes_test (void)
{
    RUN_TEST(unittest_setting_client_cert);
    RUN_TEST(unittest_attempt_to_set_client_cert_with_null_conf);
    RUN_TEST(unittest_setting_client_certificate_twice);
    RUN_TEST(unittest_serdes_conf_deep_copy);
    RUN_TEST(unittest_setting_min_tls_version);
    RUN_TEST(unittest_setting_incorrect_min_tls_version);
    RUN_TEST(unittest_attempt_to_set_client_cert_with_null_errstr);
    RUN_TEST(unittest_setting_client_cert_via_conf_properties);
    RUN_TEST(unittest_unsetting_client_cert_property);
    RUN_TEST(unittest_serdes_new_keeps_tls_conf);
}
