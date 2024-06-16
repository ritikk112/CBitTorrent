#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;
json decode_bencoded_value_int(const std::string& encoded_value) {
    size_t finish_index = encoded_value.find('e');
    if (finish_index != std::string::npos) {
        std::string num = encoded_value.substr(1, finish_index - 1);
        return json(stoll(num));
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}
json decode_bencoded_value_string(const std::string& encoded_value) {
    // Example: "5:hello" -> "hello"
    size_t colon_index = encoded_value.find(':');
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(0, colon_index);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);
        return json(str);
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}
json decode_bencoded_list(const std::string& encoded_value, int& index ) {
    std::vector<json> decoded_value;
    while (index < encoded_value.size()) {
        if (encoded_value[index] == 'e'){
            index++;
            return json(decoded_value);
        }
        if (std::isdigit(encoded_value[index])) {
            size_t colon_index = encoded_value.find(':', index);
            std::string number_string = encoded_value.substr(index,  colon_index - index);
            int64_t number = std::atoll(number_string.c_str());
            std::string str = encoded_value.substr(colon_index + 1, number);
            decoded_value.push_back(json(str));
            index = colon_index + number + 1;
        }else if (encoded_value[index] == 'l') {
            index++;
            decoded_value.push_back(decode_bencoded_list(encoded_value, index));
        }else {
            size_t finish_index = encoded_value.find( 'e', index);
            std::string num = encoded_value.substr(index + 1, finish_index - index - 1);
            decoded_value.push_back(json(std::stoll(num)));
            index = finish_index + 1;
        }
    }
    return json(decoded_value);
}
json decode_bencoded_dict(const std:: string& encoded_value, int& index) {
    std::map<json, json> dict;
    while (index < encoded_value.size()) {
        if (encoded_value[index] == 'e') {
            index++;
            continue;
        }
        size_t colon_index = encoded_value.find(':', index);
        int len = std::stoi(encoded_value.substr(index, colon_index - index));
        std::string key = encoded_value.substr(colon_index + 1, len);
        index = colon_index + len + 1;
        json val;
        if (encoded_value[index] == 'i') {
            size_t finish_index = encoded_value.find( 'e', index);
            std::string num = encoded_value.substr(index + 1, finish_index - index - 1);
            val = json(std::stoll(num));
            index = finish_index + 1;
        } else if (encoded_value[index] == 'l') {
            index++;
            val = decode_bencoded_list(encoded_value, index);
        } else if (encoded_value[index] == 'd') {
            index++;
            val = decode_bencoded_dict(encoded_value, index);
        } else {
            colon_index = encoded_value.find(':', index);
            std::string number_string = encoded_value.substr(index, colon_index);
            int64_t number = std::atoll(number_string.c_str());
            std::string str = encoded_value.substr(colon_index + 1, number);
            val = json(str);
            index = colon_index + number + 1;
        }
        dict[json(key)] = json(val);
    }
    return json(dict);
}
json decode_bencoded_value(const std::string& encoded_value) {
    if (std::isdigit(encoded_value[0])) {
        return decode_bencoded_value_string(encoded_value);
    } else if(encoded_value[0] == 'i'){
        return decode_bencoded_value_int(encoded_value);
    } else if (encoded_value[0] == 'l') {
        int index = 1;
        return decode_bencoded_list(encoded_value, index);
    }else if(encoded_value[0] == 'd'){
        int index = 1;
        return decode_bencoded_dict(encoded_value, index);
    }
    else{
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string command = argv[1];
    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
         std::string encoded_value = argv[2];
         json decoded_value = decode_bencoded_value(encoded_value);
         std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}