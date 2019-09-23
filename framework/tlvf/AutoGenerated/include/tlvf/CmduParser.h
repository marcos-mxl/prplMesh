///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

#ifndef _CmduParser_H_
#define _CmduParser_H_

#include <unordered_map>
#include <tlvf/BaseClass.h>
#include <tlvf/CmduMessageRx.h>
#include <memory>

namespace ieee1905_1{
class CmduParser{
public:
    static std::shared_ptr< std::unordered_multimap <char*,BaseClass>> getAllTlvs(CmduMessageRx &cmdu_rx);

private:
    static const char* int32ToHexCharPtr(int n);

    };
};
#endif //_CmduParser_H_

