#include "json_mini.h"

#include <cstdlib>
#include <cmath>
#include "util.h"

namespace json {

// ===========================================================================
// Value 取值
// ===========================================================================
const Value* Value::GetChild(const std::string& key) const {
    if (type != Type::Object) return nullptr;
    auto it = obj.find(key);
    if (it == obj.end() || !it->second) return nullptr;
    return it->second.get();
}

std::string Value::GetStr(const std::string& key, const std::string& def) const {
    const Value* v = GetChild(key);
    if (!v) return def;
    if (v->type == Type::String) return v->str;
    if (v->type == Type::Number) {
        char buf[64]{};
        if (v->num == (double)(long long)v->num)
            ::snprintf(buf, sizeof(buf), OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm14U1MwNUhSWGRPVldoVlYwZG9jVlZzVm5kVmJGcHlWV3RLVUZWVU1Eaz0="))))))), (long long)v->num);
        else
            ::snprintf(buf, sizeof(buf), OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm14U1MwNUhSWGxTYms1U1lrVndVbFpyVWtKUFVUMDk="))))))), v->num);
        return buf;
    }
    if (v->type == Type::Bool) return v->b ? OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm1wS01GWXlTWGhVV0dST1ZtMVNjVlZ0ZEhkVmJGcHlWV3RLVUZWVU1Eaz0="))))))) : OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1NtUXlWa2RUV0d4VlYwZDRWbFl3WkRSWFJscHlWV3RLVUZWVU1Eaz0=")))))));
    return def;
}

double Value::GetNum(const std::string& key, double def) const {
    const Value* v = GetChild(key);
    if (!v) return def;
    if (v->type == Type::Number) return v->num;
    if (v->type == Type::String) {
        try { return std::stod(v->str); } catch (...) { return def; }
    }
    return def;
}

long long Value::GetInt(const std::string& key, long long def) const {
    const Value* v = GetChild(key);
    if (!v) return def;
    if (v->type == Type::Number) return (long long)v->num;
    if (v->type == Type::String) {
        try { return std::stoll(v->str); } catch (...) { return def; }
    }
    return def;
}

bool Value::GetBool(const std::string& key, bool def) const {
    const Value* v = GetChild(key);
    if (!v) return def;
    if (v->type == Type::Bool)   return v->b;
    if (v->type == Type::Number) return v->num != 0;
    if (v->type == Type::String) return v->str == OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm1wS01GWXlTWGhVV0dST1ZtMVNjVlZ0ZEhkVmJGcHlWV3RLVUZWVU1Eaz0="))))))) || v->str == OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xMFlWbFdTbkpQVm1SU1lrVndVbFpyVWtKUFVUMDk=")))))));
    return def;
}

// ===========================================================================
// 解析器
// ===========================================================================
namespace {

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    ValuePtr ParseValue(int depth) {
        if (depth > 64) return nullptr;
        SkipWs();
        if (i_ >= s_.size()) return nullptr;

        const char c = s_[i_];
        switch (c) {
            case '{': return ParseObject(depth);
            case '[': return ParseArray(depth);
            case '"': {
                auto v = std::make_shared<Value>();
                v->type = Type::String;
                if (!ParseString(v->str)) return nullptr;
                return v;
            }
            case 't':
                if (s_.compare(i_, 4, OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm1wS01GWXlTWGhVV0dST1ZtMVNjVlZ0ZEhkVmJGcHlWV3RLVUZWVU1Eaz0=")))))))) == 0) {
                    i_ += 4;
                    auto v = std::make_shared<Value>();
                    v->type = Type::Bool; v->b = true;
                    return v;
                }
                return nullptr;
            case 'f':
                if (s_.compare(i_, 5, OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1NtUXlWa2RUV0d4VlYwZDRWbFl3WkRSWFJscHlWV3RLVUZWVU1Eaz0=")))))))) == 0) {
                    i_ += 5;
                    auto v = std::make_shared<Value>();
                    v->type = Type::Bool; v->b = false;
                    return v;
                }
                return nullptr;
            case 'n':
                if (s_.compare(i_, 4, OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm1wR2FtUXdNVmRYV0d4VlYwZDRWVmxVUW5kVmJGcHlWV3RLVUZWVU1Eaz0=")))))))) == 0) {
                    i_ += 4;
                    return std::make_shared<Value>();
                }
                return nullptr;
            default:
                return ParseNumber();
        }
    }

private:
    void SkipWs() {
        while (i_ < s_.size()) {
            const char c = s_[i_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++i_;
            else break;
        }
    }

    static void AppendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out.push_back((char)cp);
        } else if (cp < 0x800) {
            out.push_back((char)(0xC0 | (cp >> 6)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back((char)(0xE0 | (cp >> 12)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else {
            out.push_back((char)(0xF0 | (cp >> 18)));
            out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        }
    }

    bool ReadHex4(unsigned& out) {
        if (i_ + 4 > s_.size()) return false;
        unsigned v = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = s_[i_ + k];
            v <<= 4;
            if (c >= '0' && c <= '9')      v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        i_ += 4;
        out = v;
        return true;
    }

    bool ParseString(std::string& out) {
        out.clear();
        if (i_ >= s_.size() || s_[i_] != '"') return false;
        ++i_;
        while (i_ < s_.size()) {
            const char c = s_[i_++];
            if (c == '"') return true;
            if (c != '\\') { out.push_back(c); continue; }
            if (i_ >= s_.size()) return false;

            const char e = s_[i_++];
            switch (e) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    unsigned cp = 0;
                    if (!ReadHex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        // 代理对
                        if (i_ + 1 < s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
                            i_ += 2;
                            unsigned lo = 0;
                            if (!ReadHex4(lo)) return false;
                            if (lo >= 0xDC00 && lo <= 0xDFFF)
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                    }
                    AppendUtf8(out, cp);
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    ValuePtr ParseNumber() {
        const size_t start = i_;
        if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
        bool any = false;
        while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') { ++i_; any = true; }
        if (i_ < s_.size() && s_[i_] == '.') {
            ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') { ++i_; any = true; }
        }
        if (any && i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') ++i_;
        }
        if (!any) return nullptr;

        auto v = std::make_shared<Value>();
        v->type = Type::Number;
        v->num  = ::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
        return v;
    }

    ValuePtr ParseArray(int depth) {
        auto v = std::make_shared<Value>();
        v->type = Type::Array;
        ++i_;   // '['
        SkipWs();
        if (i_ < s_.size() && s_[i_] == ']') { ++i_; return v; }

        for (;;) {
            auto item = ParseValue(depth + 1);
            if (!item) return nullptr;
            v->arr.push_back(item);
            SkipWs();
            if (i_ >= s_.size()) return nullptr;
            if (s_[i_] == ',') { ++i_; continue; }
            if (s_[i_] == ']') { ++i_; return v; }
            return nullptr;
        }
    }

    ValuePtr ParseObject(int depth) {
        auto v = std::make_shared<Value>();
        v->type = Type::Object;
        ++i_;   // '{'
        SkipWs();
        if (i_ < s_.size() && s_[i_] == '}') { ++i_; return v; }

        for (;;) {
            SkipWs();
            std::string key;
            if (!ParseString(key)) return nullptr;
            SkipWs();
            if (i_ >= s_.size() || s_[i_] != ':') return nullptr;
            ++i_;
            auto item = ParseValue(depth + 1);
            if (!item) return nullptr;
            v->obj[key] = item;
            SkipWs();
            if (i_ >= s_.size()) return nullptr;
            if (s_[i_] == ',') { ++i_; continue; }
            if (s_[i_] == '}') { ++i_; return v; }
            return nullptr;
        }
    }

    const std::string& s_;
    size_t             i_ = 0;
};

} // namespace

ValuePtr Parse(const std::string& text) {
    if (text.empty()) return nullptr;
    // 跳过可能存在的 UTF-8 BOM
    size_t off = 0;
    if (text.size() >= 3 &&
        (unsigned char)text[0] == 0xEF &&
        (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF) {
        off = 3;
    }
    const std::string body = off ? text.substr(off) : text;
    Parser p(body);
    return p.ParseValue(0);
}

std::string EscapeString(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXhVWGhVYms1U1lrVndVbFpyVWtKUFVUMDk="))))))); break;
            case '\\': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXhiRlpOU0doU1lrVndVbFpyVWtKUFVUMDk="))))))); break;
            case '\b': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlSWGhVYms1U1lrVndVbFpyVWtKUFVUMDk=")))))));  break;
            case '\f': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlSWGhhU0U1U1lrVndVbFpyVWtKUFVUMDk=")))))));  break;
            case '\n': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlSbkpOVldSU1lrVndVbFpyVWtKUFVUMDk=")))))));  break;
            case '\r': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlTWGhVYms1U1lrVndVbFpyVWtKUFVUMDk=")))))));  break;
            case '\t': out += OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlTWGhXYms1U1lrVndVbFpyVWtKUFVUMDk=")))))));  break;
            default:
                if (c < 0x20) {
                    char buf[8]{};
                    ::snprintf(buf, sizeof(buf), OBFA(OBFA(OBFA(OBFA(OBFA(OBFA(OBFA("Vm0xd1ExWXlTWGhYYmxKVVlURndUMVpzV21GV01XeFlaVVZhVUZWVU1Eaz0="))))))), c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    return out;
}

} // namespace json
