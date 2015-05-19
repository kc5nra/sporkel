#pragma once

#include <fstream>
#include <type_traits>
#include <vector>

#include <boost/filesystem.hpp>

namespace sporkel_util {

template <typename T>
static typename std::enable_if<sizeof(T) == 1, void>::type
get_file_contents(const boost::filesystem::path &p, size_t size, std::vector<T> &buf)
{
	std::ifstream f(p.native(), std::ios::binary);
	buf.resize(size);
	f.read(reinterpret_cast<char *>(buf.data()), size);
}

template <typename T>
static typename std::enable_if<sizeof(T) == 1, void>::type
set_file_contents(const boost::filesystem::path &p, T *data, size_t len)
{
	std::ofstream f(p.native(), std::ios::binary);
	f.write(reinterpret_cast<const char *>(data), len);
}

}
