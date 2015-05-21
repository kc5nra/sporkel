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

namespace fs = boost::filesystem;

static fs::path& path_append(fs::path &this_, fs::path::iterator begin_, fs::path::iterator end_)
{
	for (; begin_ != end_; ++begin_)
		this_ /= *begin_;
	return this_;
}

static fs::path make_path_relative(fs::path a_From, fs::path a_To)
{
	a_From = absolute(a_From); a_To = absolute(a_To);
	fs::path ret;
	fs::path::const_iterator itrFrom(a_From.begin()), itrTo(a_To.begin());
	for (fs::path::const_iterator toEnd(a_To.end()), fromEnd(a_From.end());
		itrFrom != fromEnd && itrTo != toEnd && *itrFrom == *itrTo; 
		++itrFrom, ++itrTo);

	for (fs::path::const_iterator fromEnd(a_From.end()); itrFrom != fromEnd; ++itrFrom)
	{
		if ((*itrFrom) != ".")
			ret /= "..";
	}

	return path_append(ret, itrTo, a_To.end());
}

static bool copy_directory_recursive(const fs::path &from, const fs::path &to)
{
	using namespace fs;

	if (!create_directory(to)) {
		return false;
	}

	recursive_directory_iterator end;
	for (recursive_directory_iterator i(from); i != end; ++i) {
		if (!is_directory(i->status()) && !is_regular_file(i->status()) && !is_symlink(i->status())) {
			continue;
		}
		
		path rel_path(make_path_relative(from, i->path()));

		if (is_symlink(i->status())) {
			create_symlink(read_symlink(i->path()), to / rel_path);
			continue;
		}
		if (is_directory(i->status())) {
			copy_directory(i->path(), to / rel_path);
			continue;
		}
		if (is_regular_file(i->status())) {	
			copy_file(i->path(), to / rel_path);
			continue;
		}
	}

	return true;
}

}
