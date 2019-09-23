///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////
#include <tlvf/CmduParser.h>
#include <algorithm>
#include <vector>
#include <json-c/json.h>
#include <tlvf/ieee_1905_1/tlvUnknown.h>
#include <easylogging++.h>

using namespace ieee1905_1;

std::shared_ptr< std::unordered_multimap <char*,BaseClass>> CmduParser::getAllTlvs(CmduMessageRx &cmdu_rx)
{
    // vector of all tlvs in the cmdu,
    // later to be flushed into an unordered multimap (hashtable)
    auto tlvs = std::vector<int>();

    //get the message type from the cmdu_rx and convert it into a string for use with json
    auto msg_type = cmdu_rx.getMessageType();
    const char *type_hex = CmduParser::int32ToHexCharPtr((int)msg_type);
    char type_hex_str[6];
    strcpy(type_hex_str,type_hex);//the function only likes char arrays so that's life

    LOG(DEBUG)<<"~~~GETTING TLVS THE SMART WAY~~~";
    // deserialize the json config file
    auto json = json_object_from_file("/home/gal/work/dev2/prplMesh/framework/tlvf/cmdu_format.json");

    //find cmdu type segment
    json_object *cmdu_json;
    json_object_object_get_ex(json,"cmdu_type",&cmdu_json);
    LOG(DEBUG) << "cmdu_type subobject:\n" << json_object_to_json_string(cmdu_json);
    
    //find the relevant message's segment
    LOG(DEBUG)<<"msg type in hex: "<< type_hex_str;
    json_object *msgtype_json;
    json_object_object_get_ex(cmdu_json,type_hex_str,&msgtype_json);
    LOG(DEBUG)<<"msg json object:"<<json_object_to_json_string(msgtype_json);


    while (int tlv = cmdu_rx.getNextTlvType()!=0)
    {
        tlvs.push_back(tlv);
        auto tmp = cmdu_rx.addClass<tlvUnknown>();
    }



    return nullptr;
}

//@brief converts a 32 bit integer into a hex notation char*
const char* CmduParser::int32ToHexCharPtr(int n)
{
    std::stringstream stream;
    stream << std::hex << n;
    auto res = stream.str();
    size_t len = res.length();
    //convert to uppercase
    std::transform(res.begin(),res.end(),res.begin(),::toupper);
    //add preceding zeroes to match format in YAMLs
    for (size_t i = 0; i < 4-len; i++)
    {
        res = "0"+res;
    }
    res = "0x"+res;
    return res.c_str();

}