#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <boost/algorithm/string.hpp>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <istream>
#include <streambuf>

std::ostream& render_printable_chars(std::ostream& os, const char* buffer,
				     size_t bufsize) {
	os << " | ";
	for (size_t i = 0; i < bufsize; ++i) {
		if (std::isprint(buffer[i])) {
			os << buffer[i];
		} else {
			os << ".";
		}
	}
	return os;
}

std::ostream& hex_dump(std::ostream& os, const uint8_t* buffer, size_t bufsize,
		       bool showPrintableChars = true) {
	auto oldFormat = os.flags();
	auto oldFillChar = os.fill();

	os << std::hex;
	os.fill('0');
	bool printBlank = false;
	size_t i = 0;
	for (; i < bufsize; ++i) {
		if (i % 8 == 0) {
			if (i != 0 && showPrintableChars) {
				render_printable_chars(
				    os,
				    reinterpret_cast<const char*>(&buffer[i] -
								  8),
				    8);
			}
			os << std::endl;
			printBlank = false;
		}
		if (printBlank) {
			os << ' ';
		}
		os << std::setw(2) << std::right << unsigned(buffer[i]);
		if (!printBlank) {
			printBlank = true;
		}
	}
	if (i % 8 != 0 && showPrintableChars) {
		for (size_t j = 0; j < 8 - (i % 8); ++j) {
			os << "   ";
		}
		render_printable_chars(
		    os, reinterpret_cast<const char*>(&buffer[i] - (i % 8)),
		    (i % 8));
	}

	os << std::endl;

	os.fill(oldFillChar);
	os.flags(oldFormat);

	return os;
}

std::ostream& hex_dump(std::ostream& os, const std::string& buffer,
		       bool showPrintableChars = true) {
	return hex_dump(os, reinterpret_cast<const uint8_t*>(buffer.data()),
			buffer.length(), showPrintableChars);
}

#define FLETCHER_CHECKSUM_VALIDATE 0xffff
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX 4102U /* 5802 should be fine */

/* To be consistent, offset is 0-based index, rather than the 1-based
   index required in the specification ISO 8473, Annex C.1 */
/* calling with offset == FLETCHER_CHECKSUM_VALIDATE will validate the checksum
   without modifying the buffer; a valid checksum returns 0 */
uint16_t fletcher_checksum(uint8_t* buffer, const size_t len,
			   const uint16_t offset) {
	uint8_t* p;
	int x, y, c0, c1;
	uint16_t checksum = 0;
	uint16_t* csum;
	size_t partial_len, i, left = len;

	if (offset != FLETCHER_CHECKSUM_VALIDATE)
	/* Zero the csum in the packet. */
	{
		// assert(offset
		//       < (len - 1)); /* account for two bytes of checksum */
		if (offset >= (len - 1)) {
			std::cout << "Warning, offset equal or more than len-1"
				  << std::endl;
		}
		csum = (uint16_t*)(buffer + offset);
		*(csum) = 0;
	}

	p = buffer;
	c0 = 0;
	c1 = 0;

	while (left != 0) {
		partial_len = MIN(left, MODX);

		for (i = 0; i < partial_len; i++) {
			c0 = c0 + *(p++);
			c1 += c0;
		}

		c0 = c0 % 255;
		c1 = c1 % 255;

		left -= partial_len;
	}

	/* The cast is important, to ensure the mod is taken as a signed value.
	 */
	x = (int)((len - offset - 1) * c0 - c1) % 255;

	if (x <= 0) x += 255;
	y = 510 - c0 - x;
	if (y > 255) y -= 255;

	if (offset == FLETCHER_CHECKSUM_VALIDATE) {
		checksum = (c1 << 8) + c0;
	} else {
		/*
		 * Now we write this to the packet.
		 * We could skip this step too, since the checksum returned
		 * would
		 * be stored into the checksum field by the caller.
		 */
		buffer[offset] = x;
		buffer[offset + 1] = y;

		/* Take care of the endian issue */
		checksum = htons((x << 8) | (y & 0xFF));
	}

	return checksum;
}

class IPv6Address {
    public:
	IPv6Address();

	bool fromString(const char* addrstr);
	unsigned char* getAddr() { return &_address[0]; }

	void print();

    private:
	unsigned char _address[16];
} __attribute__((__packed__));

IPv6Address::IPv6Address() { memset(_address, 0, sizeof(_address)); }

#define MAX_IPV6_ADDRESS_STR_LEN 39

static int8_t asciiToHex(char c) {
	c |= 0x20;

	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return (c - 'a') + 10;
	} else {
		return -1;
	}
}

bool IPv6Address::fromString(const char* addrstr) {
	uint16_t accumulator = 0;
	uint8_t colon_count = 0;
	uint8_t pos = 0;

	memset(_address, 0, sizeof(_address));

	// Step 1: look for position of ::, and count colons after it
	for (uint8_t i = 1; i <= MAX_IPV6_ADDRESS_STR_LEN; i++) {
		if (addrstr[i] == ':') {
			if (addrstr[i - 1] == ':') {
				// Double colon!
				colon_count = 14;
			} else if (colon_count) {
				// Count backwards the number of colons after
				// the ::
				colon_count -= 2;
			}
		} else if (addrstr[i] == '\0') {
			break;
		}
	}

	// Step 2: convert from ascii to binary
	for (uint8_t i = 0; i <= MAX_IPV6_ADDRESS_STR_LEN && pos < 16; i++) {
		if (addrstr[i] == ':' || addrstr[i] == '\0') {
			_address[pos] = accumulator >> 8;
			_address[pos + 1] = accumulator;
			accumulator = 0;

			if (colon_count && i && addrstr[i - 1] == ':') {
				pos = colon_count;
			} else {
				pos += 2;
			}
		} else {
			int8_t val = asciiToHex(addrstr[i]);
			if (val == -1) {
				// Not hex or colon: fail
				return 0;
			} else {
				accumulator <<= 4;
				accumulator |= val;
			}
		}

		if (addrstr[i] == '\0') break;
	}

	// Success
	return 1;
}

std::unique_ptr<unsigned char[]> num_to_array(std::string& num_str,
					      unsigned int size) {
	unsigned int num{};
	if (!num_str.find("0x")) {
		num_str.erase(0, 2);
		num = std::stol(num_str, 0, 16);
	} else {
		num = std::stol(num_str);
	}

	std::unique_ptr<unsigned char[]> num_ptr(new unsigned char[size]{});
	unsigned char* num_array = num_ptr.get();
	for (unsigned int i = 0; i < size; i++) {
		num_array[i] = (num >> (size - i - 1) * 8) & 0xFF;
	}
	return num_ptr;
}

std::unique_ptr<unsigned char[]> ip_to_array(std::string& ip_str) {
	std::string ip_addr_delimiter = ".";
	unsigned int pos{};
	std::unique_ptr<unsigned char[]> ip_ptr(new unsigned char[4]{});
	unsigned char* ip_array = ip_ptr.get();

	std::string ip_part_1{}, ip_part_2{}, ip_part_3{}, ip_part_4{};

	pos = ip_str.find(ip_addr_delimiter);
	ip_part_1 = ip_str.substr(0, pos);
	ip_str.erase(0, pos + ip_addr_delimiter.length());
	pos = ip_str.find(ip_addr_delimiter);
	ip_part_2 = ip_str.substr(0, pos);
	ip_str.erase(0, pos + ip_addr_delimiter.length());
	pos = ip_str.find(ip_addr_delimiter);
	ip_part_3 = ip_str.substr(0, pos);
	ip_str.erase(0, pos + ip_addr_delimiter.length());
	ip_part_4 = ip_str;

	ip_array[0] = static_cast<unsigned char>(std::stoi(ip_part_1, 0, 10));
	ip_array[1] = static_cast<unsigned char>(std::stoi(ip_part_2, 0, 10));
	ip_array[2] = static_cast<unsigned char>(std::stoi(ip_part_3, 0, 10));
	ip_array[3] = static_cast<unsigned char>(std::stoi(ip_part_4, 0, 10));
	return ip_ptr;
}

std::unique_ptr<unsigned char[]> area_to_bytes(std::string& area_str) {
	std::string area_part1{},area_part2{};
	std::unique_ptr<unsigned char[]> area_ptr(
	    new unsigned char[(area_str.length() / 2)]{});
	for (size_t i = 0, j = 0; i < area_str.length() && j < area_str.length();
	     i += 2, j++) {
		area_part1 = area_str[i];
                area_part2 = area_str[i+1];
		(area_ptr.get())[j] =
		    static_cast<unsigned char>(16*std::stoi(area_part1, 0, 16) + std::stoi(area_part2, 0, 16));
	}

	return area_ptr;
}

