#include <filesystem>
#include <algorithm>

#include <sodium.h>

using namespace std::tr2;

bool has_option(char **begin, char **end, const std::string &option)
{
	return std::find(begin, end, option) != end;
}

#define GET_OPTION(x) get_option(argv, argv + argc, x)
#define HAS_OPTION(x) has_option(argv, argv + argc, x)
#define OPTION(x) (x < argc ? argv[x] : NULL)

int create(char *before_tree, char *after_tree, char *patch_file);
int apply(char *tree, char *patch_file);
int show_help(int result, std::string &bn) {
	if (result == 1) {		printf("usage: %s <command> <args>\n\n", bn.c_str());		printf("    create <before_tree> <after_tree> <patch_file>\n", bn.c_str());		printf("    apply <tree> <patch_file>\n", bn.c_str());
	}
	return result;
}

int main(int argc, char **argv)
{
		std::string bn = sys::basename(sys::path(argv[0]));

	if (HAS_OPTION("-h") || HAS_OPTION("--help")) {
		return show_help(1, bn);
	}

	int result = 0;

	bool is_create = HAS_OPTION("create");
	bool is_apply = HAS_OPTION("apply");
	if (is_create ^ is_apply) {
		if (is_create)
			result = create(OPTION(2), OPTION(3), OPTION(4));
		else
			result = apply(OPTION(2), OPTION(3));
	}
	else {
		fprintf(stderr, "error: create or apply command must be specified\n");
		result = 1;
	}

	return show_help(result, bn);
}

int create(char *before_tree, char *after_tree, char *patch_file){	if (!before_tree) {		fprintf(stderr, "error: <before_tree> missing\n");		return 1;	}	if (!after_tree) {		fprintf(stderr, "error: <after_tree> missing\n");		return 1;	}	if (!patch_file) {		fprintf(stderr, "error: <patch_file> missing\n");		return 1;	}	sys::path before_path(before_tree);	sys::path after_path(after_tree);	sys::path patch_path(patch_file);		if (!sys::is_directory(before_path)) {		fprintf(stderr, "error: <before_tree> '%s' is not a directory\n", before_path.string().c_str());		return 1;	}	if (!sys::is_directory(after_path)) {		fprintf(stderr, "error: <after_tree> option '%s' is not a directory\n", after_path.string().c_str());		return 1;	}	if (sys::exists(patch_path)) {		fprintf(stderr, "error: <patch_file> '%s' already exists\n", patch_path.string().c_str());		return 2;	}	return 0;}int apply(char *tree, char *patch_file){	return 0;}