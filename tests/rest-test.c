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

#include <stdlib.h>
#include <string.h>
#include "test-macros.h"
#include "serdes_int.h"

char *url_encode (const char *orig);

static void unittest_url_encode (void) {
        /* Tuples of input urls and expected output */
        const char *test[] = {
                "", "",
                "http://", "http://",
                "localhost:1234/", "localhost:1234/",

                "http://aba:laba@domain.com/with/a1",
                "http://aba:laba@domain.com/with/a1",

                "https://\\cpt:h$dd0ck!@mysite__.com",
                "https://%5Ccpt:h%24dd0ck%21@mysite__.com",

                ":!@.", ":%21@.",

                "https://:@empty.com", "https://:@empty.com",
                "https://a:@empty.com", "https://a:@empty.com",
                "https://:b@empty.com", "https://:b@empty.com",
                "https://:@", "https://:@",

                NULL, NULL,
        };
        int i;
        int fails = 0;

        for (i = 0 ; test[i] ; i += 2) {
                const char *input = test[i];
                const char *exp = test[i+1];
                char *encoded;

                encoded = url_encode(input);
                if (strcmp(encoded, exp)) {
                        fprintf(stderr, "%s: expected %s for %s, not %s\n",
                                __FUNCTION__, exp, input, encoded);
                        fails++;
                }

                free(encoded);
        }

        assert(!fails);
}

void client_cert_clear (client_cert_t *cc);

static void unittest_client_cert_clear (void) {
        client_cert_t cc;

        cc.ca_location          = strdup("ca_location");
        cc.certificate_location = strdup("certificate_location");
        cc.key_location         = strdup("key_location");
        cc.key_password         = NULL;

        client_cert_clear(&cc);

        assert(cc.ca_location == NULL);
        assert(cc.certificate_location == NULL);
        assert(cc.key_location == NULL);
        assert(cc.key_password == NULL);
}

void register_rest_test (void) {
    RUN_TEST(unittest_url_encode);
    RUN_TEST(unittest_client_cert_clear);
}
