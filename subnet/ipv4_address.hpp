#ifndef COLLECTION_IPV4_ADDRESS_HPP
#define COLLECTION_IPV4_ADDRESS_HPP


#include <string>
#include <sstream>
#include <bitset>

#include <cstdint>
#include <climits>
#include <cassert>


namespace collection{

    class ipv4_address{
    public:
        static constexpr std::size_t nbits = sizeof(std::uint32_t) * CHAR_BIT;

        using bitset_t = std::bitset<sizeof(std::uint32_t) * CHAR_BIT>;
        using octet_t = unsigned char;

        ipv4_address(){}

        explicit ipv4_address(std::uint32_t value)
            : ip{ value } {}

        ipv4_address(octet_t o1, octet_t o2, octet_t o3, octet_t o4){
            ip |= static_cast<std::uint32_t>(o1) << 24;
            ip |= static_cast<std::uint32_t>(o2) << 16;
            ip |= static_cast<std::uint32_t>(o3) << 8;
            ip |= static_cast<std::uint32_t>(o4);
        }

        ipv4_address(const std::string& s){
            set_ip(s);
        }

        ipv4_address(const ipv4_address&) = default;
        ipv4_address& operator= (const ipv4_address&) = default;

        ipv4_address(ipv4_address&&) = default;
        ipv4_address& operator= (ipv4_address&&) = default;

        void set_ip(const std::string& ip_str){
            std::stringstream stream{ ip_str };
            std::uint32_t octet{};
            unsigned char c;

            if (!(stream >> octet >> c) || octet > 255 || c != '.')
                throw std::runtime_error{ "Cannot parse IP address '" + ip_str + '\'' };

            ip |= octet << 24;

            if (!(stream >> octet >> c) || octet > 255 || c != '.')
                throw std::runtime_error{ "Cannot parse IP address '" + ip_str + '\'' };

            ip |= octet << 16;

            if (!(stream >> octet >> c) || octet > 255 || c != '.')
                throw std::runtime_error{ "Cannot parse IP address '" + ip_str + '\'' };

            ip |= octet << 8;

            if (!(stream >> octet) || octet > 255)
                throw std::runtime_error{ "Cannot parse IP address '" + ip_str + '\'' };

            ip |= octet;
        }

        ipv4_address get_network(const ipv4_address& netmask) const{
            return ipv4_address{ ip & netmask.ip };
        }

        ipv4_address get_network(std::size_t netbits) const{
            return ipv4_address{ ip & (((1 << netbits) - 1) << (nbits - netbits)) };
        }

        ipv4_address get_broadcast(const ipv4_address& netmask) const{
            return ipv4_address{ ip | ~netmask.ip };
        }

        ipv4_address get_broadcast(std::size_t netbits) const{
            return ipv4_address{ ip | ((1 << (nbits - netbits)) - 1) };
        }

        std::size_t get_total_hosts(const ipv4_address& netmask) const{
            return get_broadcast(netmask).ip - get_network(netmask).ip + 1;
        }

        std::size_t get_total_hosts(std::size_t netbits) const{
            return get_broadcast(netbits).ip - get_network(netbits).ip + 1;
        }

        std::size_t get_usable_hosts(const ipv4_address& netmask) const{
            auto total = get_total_hosts(netmask);
            return total > 1 ? total - 2 : 0;
        }

        std::size_t get_usable_hosts(std::size_t netbits) const{
            auto total = get_total_hosts(netbits);
            return total > 1 ? total - 2 : 0;
        }

        ipv4_address get_first_ip(const ipv4_address& netmask) const{
            if (!get_usable_hosts(netmask))
                return ipv4_address{};

            return ipv4_address{ get_network(netmask).ip + 1 };
        }

        ipv4_address get_first_ip(std::size_t netbits) const{
            if (!get_usable_hosts(netbits))
                return ipv4_address{};

            return ipv4_address{ get_network(netbits).ip + 1 };
        }

        ipv4_address get_last_ip(const ipv4_address& netmask){
            if (!get_usable_hosts(netmask))
                return ipv4_address{};

            return ipv4_address{ get_broadcast(netmask).ip - 1 };
        }

        ipv4_address get_last_ip(std::size_t netbits){
            if (!get_usable_hosts(netbits))
                return ipv4_address{};

            return ipv4_address{ get_broadcast(netbits).ip - 1 };
        }

        std::uint32_t native() const{
            return ip;
        }

        std::string string() const{
            std::string s;

            s = std::to_string(ip >> 24) + '.';
            s += std::to_string((ip >> 16) & 0xff) + '.';
            s += std::to_string((ip >> 8) & 0xff) + '.';
            s += std::to_string(ip & 0xff);

            return s;
        }

        bool operator== (const ipv4_address& rhs) const{
            return ip == rhs.ip;
        }

        bool operator!= (const ipv4_address& rhs) const{
            return ip != rhs.ip;
        }

        bool operator< (const ipv4_address& rhs) const{
            return ip < rhs.ip;
        }

        bool operator> (const ipv4_address& rhs) const{
            return ip > rhs.ip;
        }

        bool operator<= (const ipv4_address& rhs) const{
            return ip <= rhs.ip;
        }

        bool operator>= (const ipv4_address& rhs) const{
            return ip >= rhs.ip;
        }

    private:
        std::uint32_t ip{};
    };


    inline bool is_valid_netmask(std::uint32_t ip){
        return ipv4_address::bitset_t(~ip + 1).count() == 1;
    }


    inline bool is_valid_netmask(const ipv4_address& ip){
        return is_valid_netmask(ip.native());
    }


    inline ipv4_address netbits2netmask(std::size_t netbits){
        return ipv4_address{ ((static_cast<std::uint32_t>(1) << netbits) - 1) << (ipv4_address::nbits - netbits) };
    }


    inline std::size_t netmask2netbits(std::uint32_t netmask){
        assert(is_valid_netmask(netmask));
        return ipv4_address::bitset_t(netmask).count();
    }


    inline std::size_t netmask2netbits(const ipv4_address ip){
        return netmask2netbits(ip.native());
    }


    inline std::ostream& operator<< (std::ostream& out, const ipv4_address& ip){
        return out << ip.string();
    }

}


#endif
