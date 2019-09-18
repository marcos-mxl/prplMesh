
#include <vector>
#include <unordered_map>
#include <json-c/json.h>
#include <memory>
#include <BaseClass.h>
#include <CmduMessageRx.h>
#include <tlvUnknown.h>

using namespace ieee1905_1;

    class CmduParser{

        std::shared_ptr< std::unordered_multimap <char*,BaseClass>> CmduParser::getAllTlvs(CmduMessageRx &cmdu_rx)
        {
            // deserialize the json config file
            auto json = json_object_from_file("framework/tlvf/cmdu_format.json");
            
            // vector of all tlvs in the cmdu,
            // later to be flushed into an unordered multimap (hashtable)
            auto tlvs = std::vector<int>();
            auto type = cmdu_rx.getMessageType();
            while (int tlv = cmdu_rx.getNextTlvType()!=0)
            {
                tlvs.push_back(tlv);
                auto tmp = cmdu_rx.addClass<tlvUnknown>();
            }
            auto type_hex_str =int32ToHexCharArray((int)type);
            auto cmdu_types =json_object_object_get(json,"cmdu_type");
            auto msg_type = json_object_object_get(cmdu_types,type_hex_str);



            return nullptr;
        }

        //@brief converts a <=32 bit integer into a hex notation char array
        //reference: https://stackoverflow.com/questions/10770257/c-programming-convert-hex-int-to-char
        char* int32ToHexCharArray(int n)
        {
            char str[9];
            sprintf(str,"%x",n);
            return str;
        }
    };