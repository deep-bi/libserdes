/**
 * Copyright 2025 Confluent Inc.
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
    assert(!strcmp(sconf->client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf->client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf->client_cert.key_location, "key_location"));
    assert(sconf->client_cert.key_password == NULL);

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

    serdes_conf_set_client_cert(sconf,
                                dummy_string,
                                dummy_string,
                                dummy_string,
                                dummy_string,
                                err_buf, sizeof(err_buf));

    serdes_conf_set_client_cert(sconf,
                          "ca_location",
                          "certificate_location",
                          "key_location",
                          "key_password",
                          err_buf, sizeof(err_buf));

    assert(err_buf[0] == '\0');
    assert(!strcmp(sconf->client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf->client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf->client_cert.key_location, "key_location"));
    assert(!strcmp(sconf->client_cert.key_password, "key_password"));

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
    assert(!strcmp(sconf_copy->client_cert.ca_location, "ca_location"));
    assert(!strcmp(sconf_copy->client_cert.certificate_location, "certificate_location"));
    assert(!strcmp(sconf_copy->client_cert.key_location, "key_location"));
    assert(sconf_copy->client_cert.key_password == NULL);

    assert(sconf_copy->client_cert.ca_location != sconf->client_cert.ca_location);
    assert(sconf_copy->client_cert.certificate_location != sconf->client_cert.certificate_location);
    assert(sconf_copy->client_cert.key_location != sconf->client_cert.key_location);
    assert(sconf_copy->client_cert.key_password == sconf->client_cert.key_password);

    serdes_conf_destroy(sconf);
    serdes_conf_destroy(sconf_copy);
}

void register_serdes_test (void)
{
    RUN_TEST(unittest_setting_client_cert);
    RUN_TEST(unittest_attempt_to_set_client_cert_with_null_conf);
    RUN_TEST(unittest_setting_client_certificate_twice);
    RUN_TEST(unittest_serdes_conf_deep_copy);
}
