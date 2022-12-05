#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

