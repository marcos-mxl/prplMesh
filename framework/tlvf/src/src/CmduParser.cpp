#include <tlvf/CmduParser.h>

#include <vector>
#include <json-c/json.h>
#include <tlvf/ieee_1905_1/tlvUnknown.h>
#include <easylogging++.h>

using namespace ieee1905_1;

std::shared_ptr< std::unordered_multimap <char*,BaseClass>> CmduParser::getAllTlvs(CmduMessageRx &cmdu_rx)
{
    LOG(DEBUG)<<"~~~GETTING TLVS THE SMART WAY~~~";
    // deserialize the json config file
    auto json = json_object_from_file("framework/tlvf/cmdu_format.json");
    LOG(DEBUG)<<"json: \n" <<json;
    // vector of all tlvs in the cmdu,
    // later to be flushed into an unordered multimap (hashtable)
    auto tlvs = std::vector<int>();
    auto msg_type = cmdu_rx.getMessageType();
    LOG(DEBUG)<<(int)msg_type;
    while (int tlv = cmdu_rx.getNextTlvType()!=0)
    {
        tlvs.push_back(tlv);
        auto tmp = cmdu_rx.addClass<tlvUnknown>();
    }
    // auto type_hex_str =int32ToHexCharArray((int)type);
    // auto cmdu_types =json_object_object_get(json,"cmdu_type");
    // auto msg_type = json_object_object_get(cmdu_types,type_hex_str);



    return nullptr;
}

//@brief converts a <=32 bit integer into a hex notation char array
//reference: https://stackoverflow.com/questions/10770257/c-programming-convert-hex-int-to-char
char* int32ToHexCharArray(int n)
{
    char *str = new char[9];
    sprintf(str,"%x",n);
    return str;
}