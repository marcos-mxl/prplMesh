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

#include <tlvf/wfa_map/tlvSteeringRequest.h>
#include <tlvf/tlvflogging.h>

using namespace wfa_map;

tlvSteeringRequest::tlvSteeringRequest(uint8_t* buff, size_t buff_len, bool parse, bool swap_needed) :
    BaseClass(buff, buff_len, parse, swap_needed) {
    m_init_succeeded = init();
}
tlvSteeringRequest::tlvSteeringRequest(std::shared_ptr<BaseClass> base, bool parse, bool swap_needed) :
BaseClass(base->getBuffPtr(), base->getBuffRemainingBytes(), parse, swap_needed){
    m_init_succeeded = init();
}
tlvSteeringRequest::~tlvSteeringRequest() {
}
const eTlvTypeMap& tlvSteeringRequest::type() {
    return (const eTlvTypeMap&)(*m_type);
}

const uint16_t& tlvSteeringRequest::length() {
    return (const uint16_t&)(*m_length);
}

sMacAddr& tlvSteeringRequest::bssid() {
    return (sMacAddr&)(*m_bssid);
}

tlvSteeringRequest::sRequestFlags& tlvSteeringRequest::request_flags() {
    return (sRequestFlags&)(*m_request_flags);
}

uint16_t& tlvSteeringRequest::steering_opportunity_window_sec() {
    return (uint16_t&)(*m_steering_opportunity_window_sec);
}

uint16_t& tlvSteeringRequest::btm_disassociation_timer() {
    return (uint16_t&)(*m_btm_disassociation_timer);
}

uint8_t& tlvSteeringRequest::sta_list_length() {
    return (uint8_t&)(*m_sta_list_length);
}

std::tuple<bool, sMacAddr&> tlvSteeringRequest::sta_list(size_t idx) {
    bool ret_success = ( (m_sta_list_idx__ > 0) && (m_sta_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_sta_list[ret_idx]);
}

bool tlvSteeringRequest::alloc_sta_list(size_t count) {
    if (m_lock_order_counter__ > 0) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list sta_list, abort!";
        return false;
    }
    if (count == 0) {
        TLVF_LOG(WARNING) << "can't allocate 0 bytes";
        return false;
    }
    size_t len = sizeof(sMacAddr) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 0;
    uint8_t *src = (uint8_t *)&m_sta_list[*m_sta_list_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_target_bssid_list_length = (uint8_t *)((uint8_t *)(m_target_bssid_list_length) + len);
    m_target_bssid_list = (sTargetBssidInfo *)((uint8_t *)(m_target_bssid_list) + len);
    m_sta_list_idx__ += count;
    *m_sta_list_length += count;
    if (!buffPtrIncrementSafe(len)) { return false; }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_sta_list_idx__ - count; i < m_sta_list_idx__; i++) { m_sta_list[i].struct_init(); }
    }
    return true;
}

uint8_t& tlvSteeringRequest::target_bssid_list_length() {
    return (uint8_t&)(*m_target_bssid_list_length);
}

std::tuple<bool, tlvSteeringRequest::sTargetBssidInfo&> tlvSteeringRequest::target_bssid_list(size_t idx) {
    bool ret_success = ( (m_target_bssid_list_idx__ > 0) && (m_target_bssid_list_idx__ > idx) );
    size_t ret_idx = ret_success ? idx : 0;
    if (!ret_success) {
        TLVF_LOG(ERROR) << "Requested index is greater than the number of available entries";
    }
    return std::forward_as_tuple(ret_success, m_target_bssid_list[ret_idx]);
}

bool tlvSteeringRequest::alloc_target_bssid_list(size_t count) {
    if (m_lock_order_counter__ > 1) {;
        TLVF_LOG(ERROR) << "Out of order allocation for variable length list target_bssid_list, abort!";
        return false;
    }
    if (count == 0) {
        TLVF_LOG(WARNING) << "can't allocate 0 bytes";
        return false;
    }
    size_t len = sizeof(sTargetBssidInfo) * count;
    if(getBuffRemainingBytes() < len )  {
        TLVF_LOG(ERROR) << "Not enough available space on buffer - can't allocate";
        return false;
    }
    m_lock_order_counter__ = 1;
    uint8_t *src = (uint8_t *)&m_target_bssid_list[*m_target_bssid_list_length];
    uint8_t *dst = src + len;
    if (!m_parse__) {
        size_t move_length = getBuffRemainingBytes(src) - len;
        std::copy_n(src, move_length, dst);
    }
    m_target_bssid_list_idx__ += count;
    *m_target_bssid_list_length += count;
    if (!buffPtrIncrementSafe(len)) { return false; }
    if(m_length){ (*m_length) += len; }
    if (!m_parse__) { 
        for (size_t i = m_target_bssid_list_idx__ - count; i < m_target_bssid_list_idx__; i++) { m_target_bssid_list[i].struct_init(); }
    }
    return true;
}

void tlvSteeringRequest::class_swap()
{
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_length));
    m_bssid->struct_swap();
    m_request_flags->struct_swap();
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_steering_opportunity_window_sec));
    tlvf_swap(16, reinterpret_cast<uint8_t*>(m_btm_disassociation_timer));
    for (size_t i = 0; i < (size_t)*m_sta_list_length; i++){
        m_sta_list[i].struct_swap();
    }
    for (size_t i = 0; i < (size_t)*m_target_bssid_list_length; i++){
        m_target_bssid_list[i].struct_swap();
    }
}

size_t tlvSteeringRequest::get_initial_size()
{
    size_t class_size = 0;
    class_size += sizeof(eTlvTypeMap); // type
    class_size += sizeof(uint16_t); // length
    class_size += sizeof(sMacAddr); // bssid
    class_size += sizeof(sRequestFlags); // request_flags
    class_size += sizeof(uint16_t); // steering_opportunity_window_sec
    class_size += sizeof(uint16_t); // btm_disassociation_timer
    class_size += sizeof(uint8_t); // sta_list_length
    class_size += sizeof(uint8_t); // target_bssid_list_length
    return class_size;
}

bool tlvSteeringRequest::init()
{
    if (getBuffRemainingBytes() < kMinimumLength) {
        TLVF_LOG(ERROR) << "Not enough available space on buffer. Class init failed";
        return false;
    }
    m_type = (eTlvTypeMap*)m_buff_ptr__;
    if (!m_parse__) *m_type = eTlvTypeMap::TLV_STEERING_REQUEST;
    if (!buffPtrIncrementSafe(sizeof(eTlvTypeMap))) { return false; }
    m_length = (uint16_t*)m_buff_ptr__;
    if (!m_parse__) *m_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) { return false; }
    m_bssid = (sMacAddr*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sMacAddr); }
    if (!m_parse__) { m_bssid->struct_init(); }
    m_request_flags = (sRequestFlags*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(sRequestFlags))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(sRequestFlags); }
    if (!m_parse__) { m_request_flags->struct_init(); }
    m_steering_opportunity_window_sec = (uint16_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_btm_disassociation_timer = (uint16_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint16_t))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint16_t); }
    m_sta_list_length = (uint8_t*)m_buff_ptr__;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_sta_list = (sMacAddr*)m_buff_ptr__;
    uint8_t sta_list_length = *m_sta_list_length;
    m_sta_list_idx__ = sta_list_length;
    if (!buffPtrIncrementSafe(sizeof(sMacAddr)*(sta_list_length))) { return false; }
    m_target_bssid_list_length = (uint8_t*)m_buff_ptr__;
    if (!m_parse__) *m_target_bssid_list_length = 0;
    if (!buffPtrIncrementSafe(sizeof(uint8_t))) { return false; }
    if(m_length && !m_parse__){ (*m_length) += sizeof(uint8_t); }
    m_target_bssid_list = (sTargetBssidInfo*)m_buff_ptr__;
    uint8_t target_bssid_list_length = *m_target_bssid_list_length;
    m_target_bssid_list_idx__ = target_bssid_list_length;
    if (!buffPtrIncrementSafe(sizeof(sTargetBssidInfo)*(target_bssid_list_length))) { return false; }
    if (m_parse__ && m_swap__) { class_swap(); }
    if (m_parse__) {
        if (*m_type != eTlvTypeMap::TLV_STEERING_REQUEST) {
            TLVF_LOG(ERROR) << "TLV type mismatch. Expected value: " << int(eTlvTypeMap::TLV_STEERING_REQUEST) << ", received value: " << int(*m_type);
            return false;
        }
    }
    return true;
}


