///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_WFA_MAP_TLVRADIOOPERATIONRESTRICTION_H_
#define _TLVF_WFA_MAP_TLVRADIOOPERATIONRESTRICTION_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include "tlvf/wfa_map/eTlvTypeMap.h"
#include "tlvf/common/sMacAddr.h"
#include <tuple>

namespace wfa_map {


class tlvRadioOperationRestriction : public BaseClass
{
    public:
        tlvRadioOperationRestriction(uint8_t* buff, size_t buff_len, bool parse = false, bool swap_needed = false);
        tlvRadioOperationRestriction(std::shared_ptr<BaseClass> base, bool parse = false, bool swap_needed = false);
        ~tlvRadioOperationRestriction();

        typedef struct sChannelInfo {
            uint8_t channel_number;
            //The minimum frequency separation (in multiples of 10 MHz) that this radio would require when operating on
            //the above channel number between the center frequency of that channel and the center operating frequency of
            //another radio (operating simultaneous TX/RX) of the Multi-AP Agent.
            uint8_t minimum_frequency_separation;
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sChannelInfo;
        
        typedef struct sOperatingClasses {
            uint8_t operating_class;
            uint8_t channel_list_length;
            sChannelInfo* channel_list; //TLVF_TODO: not supported yet
            void struct_swap(){
            }
            void struct_init(){
            }
        } __attribute__((packed)) sOperatingClasses;
        
        const eTlvTypeMap& type();
        uint16_t& length();
        sMacAddr& radio_uid();
        uint8_t& operating_classes_list_length();
        std::tuple<bool, sOperatingClasses&> operating_classes_list(size_t idx);
        bool alloc_operating_classes_list(size_t count = 1);
        void class_swap();
        static size_t get_initial_size();

    private:
        bool init();
        eTlvTypeMap* m_type = nullptr;
        uint16_t* m_length = nullptr;
        sMacAddr* m_radio_uid = nullptr;
        uint8_t* m_operating_classes_list_length = nullptr;
        sOperatingClasses* m_operating_classes_list = nullptr;
        size_t m_operating_classes_list_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: wfa_map

#endif //_TLVF/WFA_MAP_TLVRADIOOPERATIONRESTRICTION_H_
