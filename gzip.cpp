#include "gzip.h"
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>

namespace mtproto::gzip {

	mtproto::data::binary_buffer inflate(const mtproto::data::binary_buffer& compressed) {
		boost::iostreams::filtering_ostream stream;
		std::vector<char> decompressed;
		stream.push(boost::iostreams::gzip_decompressor());
		stream.push(boost::iostreams::back_inserter(decompressed));
		boost::iostreams::write(stream, (char*)compressed.get_data_pointer(), compressed.get_size());
		return mtproto::data::binary_buffer((char*)decompressed.data(), decompressed.size());
	}
}