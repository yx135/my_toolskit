#pragma once

#include <zlib.h>
#include <string>
#include <vector>
#include "Error.h"

namespace my_toolskit{

class Algorithms{
	public:
		Algorithms();
		~Algorithms();

		Error compressByGZip(const std::string& in, std::string& out);
		Error decompressByGZip(const std::string& in, std::string& out);

		std::string base64Encode(const std::string& data);
		std::string base64Encode(const std::vector<uint8_t>& data);
		std::vector<uint8_t> base64Decode(const std::string& data);
		std::string base64Decode(const std::string& data, bool);
	private:
		uLong m_boundLen;
};

}
