#include <iostream>
#include <vector>
#include <tuple>
#include <algorithm>
#include <sstream>
#include <locale>
#include <type_traits>

#include <cstdio>
#include <cctype>

#include "ipv4_address.hpp"


using namespace collection;


class apos_numpunct : public std::numpunct<char>{
protected:
    virtual char do_thousands_sep() const override{
        return '\'';
    }

    virtual std::string do_grouping() const override{
        return "\03";
    }
};


template<typename T, typename std::enable_if<std::is_integral_v<T>>::type* = nullptr>
std::string make_human_readable_integer(T&& value){
    std::stringstream stream;

    stream.imbue(std::locale{std::locale{""}, new apos_numpunct{}});
    stream << std::forward<T>(value);

    return stream.str();
}



bool iequals(const std::string& s1, const std::string& s2) {
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char c1, char c2) {
        return std::toupper(c1) == std::toupper(c2);
        });
}


void print_row(const std::string& key, const std::string& value) {
    std::printf("%-15s\t%s\n", key.c_str(), value.c_str());
}


std::pair<std::string, std::string> parse_cidr_notation(const std::string& ip) {
    std::size_t pos = ip.find('/');

    if (pos == ip.npos)
        throw std::runtime_error{ "Cannot parse CIDR notation: " + ip };

    std::string address = ip.substr(0, pos);
    std::string suffix = ip.substr(++pos);

    std::size_t netbits;

    try {
        netbits = std::stoul(suffix);
    }

    catch (const std::exception&) {
        throw std::runtime_error{ "Cannot parse CIDR suffix '" + suffix + '\'' };
    }

    std::string netmask = netbits2netmask(netbits).string();

    return std::make_pair(std::move(address), std::move(netmask));
}


std::pair<std::string, std::string> ask_params() {
    std::string line;
    std::cout << "Enter IP: ";
    std::getline(std::cin, line);

    if (line.find('/') != line.npos)
        return parse_cidr_notation(line);

    ipv4_address ip{ line };

    std::cout << "Enter subnet mask: ";
    std::getline(std::cin, line);

    ipv4_address netmask{ line };

    return std::make_pair(ip.string(), netmask.string());
}


template<typename Iterator>
std::pair<std::vector<std::string>, std::vector<std::string>> parse_arguments(Iterator begin, Iterator end) {
    std::vector<std::string> args(begin, end), ip_params, key_params, * current = std::addressof(ip_params);

    for (auto&& arg : args) {
        if (arg == "--") {
            current = std::addressof(key_params);
            continue;
        }

        current->push_back(std::move(arg));
    }

    return std::make_pair(std::move(ip_params), std::move(key_params));
}


bool find_key(const std::vector<std::string>& keys, const std::string s) {
    for (const auto& key : keys) {
        if (iequals(key, s))
            return true;
    }

    return false;
}


std::size_t netmask2netbits2(std::uint32_t netmask) {
    return std::bitset<sizeof(std::uint32_t)* CHAR_BIT>(netmask).count();
}


int main(int argc, char** argv) try {
    std::vector<std::string> ip_params, key_params;
    std::tie(ip_params, key_params) = parse_arguments(argv + 1, argv + argc);

    std::string ip, netmask;

    if (ip_params.size() == 0) {
        std::tie(ip, netmask) = ask_params();
    }

    else if (ip_params.size() == 1) {
        std::tie(ip, netmask) = parse_cidr_notation(ip_params[0]);
    }

    else if (ip_params.size() == 2) {
        ip = ip_params[0];
        netmask = ip_params[1];
    }

    else {
        std::cerr << "Synopsis: " << argv[0] << " <IP> [subnet mask]\n";
        return 1;
    }

    if (!is_valid_netmask(netmask))
        throw std::runtime_error{ "Invalid subnet mask '" + netmask + '\'' };

    ipv4_address address{ ip };

    std::size_t netbits = netmask2netbits(netmask);

    if (key_params.empty()) {
        auto usable = make_human_readable_integer(address.get_usable_hosts(netmask));
        auto total = make_human_readable_integer(address.get_total_hosts(netmask));

        print_row("IP:", address.string() + '/' + std::to_string(netbits));
        print_row("Network:", address.get_network(netmask).string());
        print_row("Netmask:", netmask);
        print_row("Broadcast:", address.get_broadcast(netmask).string());
        print_row("First:", address.get_first_ip(netmask).string());
        print_row("Last:", address.get_last_ip(netmask).string());
        print_row("Hosts:", usable + " / " + total);
    }
    else {
        if (find_key(key_params, "IP"))          print_row("IP:", address.string() + '/' + std::to_string(netbits));
        if (find_key(key_params, "NETWORK"))     print_row("Network:", address.get_network(netmask).string());
        if (find_key(key_params, "NETMASK"))     print_row("Netmask:", netmask);
        if (find_key(key_params, "BROADCAST"))   print_row("Broadcast:", address.get_broadcast(netmask).string());
        if (find_key(key_params, "FIRST"))       print_row("First:", address.get_first_ip(netmask).string());
        if (find_key(key_params, "LAST"))        print_row("Last:", address.get_last_ip(netmask).string());

        if (find_key(key_params, "HOST") || find_key(key_params, "HOSTS")){
            auto usable = make_human_readable_integer(address.get_usable_hosts(netmask));
            auto total = make_human_readable_integer(address.get_total_hosts(netmask));

            print_row("Hosts:", usable + " / " + total);
        }
    }
}


catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
}
