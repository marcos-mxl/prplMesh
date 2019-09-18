
#include <unordered_map>
#include <json-c/json.h>
#include <BaseClass.h>
#include <memory>
#include <CmduMessageRx.h>

namespace ieee1905_1{
class CmduParser{
public:
static std::shared_ptr< std::unordered_multimap <char*,BaseClass>> getAllTlvs(CmduMessageRx rx);
       
    };
};
