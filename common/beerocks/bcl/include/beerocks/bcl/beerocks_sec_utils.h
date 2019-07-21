/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_SEC_UTILS_H_
#define _BEEROCKS_SEC_UTILS_H_

#include <random>

namespace beerocks
{

namespace sec
{
    static inline void random_bytes(uint8_t *buffer, size_t size)
    {
        std::random_device engine;
        for (int i = 0; i < size; i++)
            buffer[i] = (uint8_t)engine();
    }

} // namespace sec
    
} // namespace beerocks

#endif //_BEEROCKS_SEC_UTILS_H_
