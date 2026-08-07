#pragma once

// ---------------------------------------------------------------------------
// 极简 JSON 解析 / 生成
//   只覆盖后端接口需要的能力：对象、数组、字符串、数字、布尔、null
//   不追求完备，但对格式错误有明确的失败返回，不会崩
// ---------------------------------------------------------------------------

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace json {

class Value;
using ValuePtr = std::shared_ptr<Value>;

enum class Type { Null, Bool, Number, String, Array, Object };

class Value {
public:
    Type type = Type::Null;

    bool                             b = false;
    double                           num = 0;
    std::string                      str;
    std::vector<ValuePtr>            arr;
    std::map<std::string, ValuePtr>  obj;

    bool IsNull()   const { return type == Type::Null; }
    bool IsObject() const { return type == Type::Object; }
    bool IsArray()  const { return type == Type::Array; }

    // 安全取值：类型不符或键不存在时返回默认值
    std::string        GetStr(const std::string& key, const std::string& def = "") const;
    double             GetNum(const std::string& key, double def = 0) const;
    long long          GetInt(const std::string& key, long long def = 0) const;
    bool               GetBool(const std::string& key, bool def = false) const;
    const Value*       GetChild(const std::string& key) const;
};

// 解析；失败返回 nullptr
ValuePtr Parse(const std::string& text);

// 字符串转义（用于手工拼 JSON）
std::string EscapeString(const std::string& s);

} // namespace json
