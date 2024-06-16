#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <map>
#include "lib/nlohmann/json.hpp"
#include <openssl/sha.h>
using json = nlohmann::json;
std::pair<std::vector<json>, int> parseTextAndExtractList(std::string encoded_value, std::vector<json> result, int counter = 1);
std::pair<json, int> decodeDictionaries(std::string encoded_value, int counter, json result);
std::string jsonToBencodedText(json &jsonValue)
{
    std::string result{"4infod"};
    for (const auto &item : jsonValue.items())
    {
        auto keyLength = std::to_string(item.key().length());
        result += (keyLength + ":");
        auto key = item.key();
        result += key;
        auto val = item.value();
        if (val.is_number())
        {
            auto num = "i" + val.dump() + "e";
            result += num;
        }
        else if (val.is_string())
        {
            // auto stringVal = std::to_string(val.dump()) + ":" + "e";
            // result += stringVal;
        }
    }
    return result;
}
void readFile(std::string fileName)
{
    json jsonResult({});
    std::ifstream ifs(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
    std::ifstream::pos_type fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<char> bytes(fileSize);
    ifs.read(bytes.data(), fileSize);
    std::string fileData = std::string(bytes.data(), fileSize);
    auto v = decodeDictionaries(fileData, 1, jsonResult);
    std::string tracker = v.first.at("announce");
    auto info = v.first.at("info");
    auto len = info.at("length");
    auto startInd = fileData.find("4:infod") + 6;
    std::string encoded_info = fileData.substr(startInd, fileData.length() - startInd - 1);
    unsigned char *charArr = new unsigned char[encoded_info.length() + 1]{'\0'};
    memcpy(charArr, &encoded_info[0], encoded_info.length());
    std::cout << "Tracker URL: " << tracker << std::endl;
    std::cout << "Length: " << len << std::endl;
    // std::cout << "Length: " << length << std::endl;
    unsigned char hash[20];
    // auto val = jsonToBencodedText(info);
    // std::cerr << val << std::endl;
    std::cerr << 2 << std::endl;
    SHA1(charArr, encoded_info.length(), hash);
    std::cout << "Info Hash: ";
    for (int i = 0; i < 20; i++)
    {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i] << "";
    }
}
std::pair<json, int> decodeDictionaries(std::string encoded_value, int counter, json result)
{
    std::string key;
    bool isKey = false;
    bool isValue = false;
    while (counter < encoded_value.length() - 1)
    {
        if (encoded_value[counter] == 'd')
        {
            counter++;
            auto v = decodeDictionaries(encoded_value, counter, {});
            counter = v.second;
            // result.push_back(v.first);
            result[key] = v.first;
        }
        else if (encoded_value[counter] == 'e')
        {
            counter++;
            return std::make_pair(result, counter);
        }
        else if (isdigit(encoded_value[counter]))
        {
            int nextIteration = counter;
            size_t colon_index = encoded_value.find(':', counter);
            if (colon_index != std::string::npos)
            {
                std::string number_string = encoded_value.substr(counter, colon_index);
                int64_t number = std::atoll(number_string.c_str());
                std::string str = encoded_value.substr(colon_index + 1, number);
                nextIteration = (colon_index + number);
                counter = nextIteration + 1;
                if (!isKey)
                {
                    key = str;
                    isKey = true;
                }
                else
                {
                    result[key] = str;
                    isKey = false;
                    key = "";
                }
            }
        }
        else if (encoded_value[counter] == 'i')
        {
            int j = counter;
            bool isNegative = false;
            int offset = counter + 1;
            if (encoded_value[j + 1] == '-')
            {
                isNegative = true;
                j++;
                offset++;
            }
            size_t endOfNumString = encoded_value.find('e', offset);
            if (endOfNumString != std::string::npos)
            {
                long long val = stoll(encoded_value.substr(offset, endOfNumString - offset));
                auto jsonVal = isNegative ? json(-val) : json(val);
                result[key] = jsonVal;
                key = "";
                isKey = false;
            }
            counter = endOfNumString + 1;
        }
        else if (encoded_value[counter] == 'l')
        {
            counter++;
            auto v = parseTextAndExtractList(encoded_value, {}, counter);
            counter = v.second;
            result[key] = v.first;
        }
    }
    return std::make_pair(result, counter);
}
std::pair<std::vector<json>, int> parseTextAndExtractList(std::string encoded_value, std::vector<json> result, int counter)
{
    while (counter < encoded_value.length())
    {
        if (encoded_value[counter] == 'e')
        {
            return std::make_pair(result, counter);
        }
        else if (encoded_value[counter] == 'l')
        {
            counter++;
            auto v = parseTextAndExtractList(encoded_value, {}, counter);
            counter = v.second + 1;
            result.push_back(v.first);
        }
        else if (isdigit(encoded_value[counter]))
        {
            int nextIteration = counter;
            size_t colon_index = encoded_value.find(':', counter);
            if (colon_index != std::string::npos)
            {
                std::string number_string = encoded_value.substr(counter, colon_index);
                int64_t number = std::atoll(number_string.c_str());
                std::string str = encoded_value.substr(colon_index + 1, number);
                nextIteration = (colon_index + number);
                counter = nextIteration + 1;
                result.push_back(json(str));
            }
        }
        else if (encoded_value[counter] == 'i')
        {
            int j = counter;
            bool isNegative = false;
            int offset = counter + 1;
            if (encoded_value[j + 1] == '-')
            {
                isNegative = true;
                j++;
                offset++;
            }
            size_t endOfNumString = encoded_value.find('e', offset);
            if (endOfNumString != std::string::npos)
            {
                long long val = stoll(encoded_value.substr(offset, endOfNumString - offset));
                result.push_back(isNegative ? json(-val) : json(val));
            }
            counter = endOfNumString + 1;
        }
    }
    return std::make_pair(result, counter);
}
std::string extractString(std::string encoded_value)
{
    if (std::isdigit(encoded_value[0]))
    {
        size_t colon_index = encoded_value.find(':');
        if (colon_index != std::string::npos)
        {
            std::string number_string = encoded_value.substr(0, colon_index);
            int64_t number = std::atoll(number_string.c_str());
            std::string str = encoded_value.substr(colon_index + 1, number);
            return str;
        }
        else
        {
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    }
    return "";
}
long long extractNum(std::string encoded_value)
{
    if (encoded_value[0] == 'i' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        if (encoded_value[1] == '-')
        {
            long long val = stoll(encoded_value.substr(2, encoded_value.length() - 3));
            return -val;
        }
        else
        {
            return stoll(encoded_value.substr(1, encoded_value.length() - 2));
        }
    }
    else
    {
        throw std::runtime_error("Not a number");
    }
}
json decode_bencoded_value(const std::string &encoded_value)
{
    if (std::isdigit(encoded_value[0]))
    {
        // Example: "5:hello" -> "hello"
        return json(extractString(encoded_value));
    }
    else if (encoded_value[0] == 'i' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        return json(extractNum(encoded_value));
    }
    else if (encoded_value[0] == 'l' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        auto list = parseTextAndExtractList(encoded_value, {}, 1);
        return json(list.first);
    }
    else if (encoded_value[0] == 'd' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        json jsonResult({});
        auto v = decodeDictionaries(encoded_value, 1, jsonResult);
        return v.first;
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string command = argv[1];
    if (command == "decode")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        std::string command_name = argv[1];
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        readFile(argv[2]);
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }
    return 0;
}