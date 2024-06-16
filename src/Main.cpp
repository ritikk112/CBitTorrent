#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include "lib/nlohmann/json.hpp"
using json = nlohmann::json;
json decode_bencoded_list(const std::string& encoded_value){
    json ans = json::array();
    size_t colon_index = encoded_value.find(':');
    char ch = encoded_value[colon_index+1];
    int i = colon_index+1;
    std::string str = "";
    while(i < encoded_value.size()){
        if(encoded_value[i] == 'i' && std::isdigit(encoded_value[i+1])){
            i++;
            std::string temp =  "";
            while(i < encoded_value.size() && ch >= '0' || ch <= '9'){
                temp += encoded_value[i++];
            }
            ans.push_back(str);
            ans.push_back(std::atoll(temp.c_str()));
            break;
        }
        str += ch;
        ch = encoded_value[++i];
    }
    return  ans;
}
json decode_bencoded_value(const std::string& encoded_value) {
    if (std::isdigit(encoded_value[0])) {
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
    else if(encoded_value[0] == 'i' && encoded_value[encoded_value.size() - 1] == 'e'){
        std::string x = encoded_value.substr(1, encoded_value.size()-2);
        return json(std::atoll(x.c_str()));
    }
    else if(encoded_value[0] == 'l' && encoded_value[encoded_value.size() - 1] == 'e'){
        return decode_bencoded_list(encoded_value.substr(1, encoded_value.size() - 2));
    }
    else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}
int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
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
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // std::cout << "Logs from your program will appear here!" << std::endl;
        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}