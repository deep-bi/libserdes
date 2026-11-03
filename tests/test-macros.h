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

#ifndef TEST_MACROS_H
#define TEST_MACROS_H

#include <assert.h>
#include <stdio.h>

#define RUN_TEST(test)                        \
    do {                                      \
        printf("  [ RUN      ] %s\n", #test); \
        test();                               \
        printf("  [       OK ] %s\n", #test); \
    } while (0)

#define RUN_SUITE(suite)                                       \
    do {                                                       \
        printf("[==========] Running suite: %s\n", #suite);    \
        suite();                                               \
        printf("[==========] Suite %s completed\n\n", #suite); \
    } while (0)

#endif // TEST_MACROS_H
