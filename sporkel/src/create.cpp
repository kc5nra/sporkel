#include "../include/sporkel.h"

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <limits>

namespace fs = boost::filesystem;
namespace b = boost;

struct sporkel_create_context
{
	b::optional<fs::path> before_path;
	b::optional<fs::path> after_path;
	b::optional<fs::path> patch_path;
	unsigned int num_threads;
	unsigned int memory_limit;
	b::optional<fs::path> cache_path;
	unsigned int lzma_preset;

	sporkel_create_context() : num_threads(1),
			memory_limit(std::numeric_limits<unsigned int>::max()),
			lzma_preset(2) {}
};