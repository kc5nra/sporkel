#include <cstring>
#include <string>
#include <iostream>
#include <thread>

#include <boost/optional.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>

#include "../util/scopeguard.hpp"
#include "../util/util.hpp"

#include <sporkel.h>

using namespace boost::filesystem;
namespace po = boost::program_options;

static bool verbose;

int create(const path &before_path, const path &after_path, const path &patch_path,
	unsigned int num_threads, unsigned int memory_limit,
	const boost::optional<path> &cache_path, unsigned int lzma_preset, bool require_exact_patch_target);

int apply(const path &before_path, const path &patch_path, bool keep_backup);
int keypair(const path &secret_key_file, const path &public_key_file);
int sign(const path &secret_key_path, const path &file_path);
int verify(const path &public_key_path, const path &file_path, const std::string &signature);

int remove_positional(po::options_description &op_desc, int pos_cnt)
{
	using namespace std;
	using options_t = remove_const<remove_reference<decltype(op_desc.options())>::type>::type;
	// remove last two arguments from help
	auto &ov = const_cast<options_t&>(op_desc.options());
	ov.resize(ov.size() - pos_cnt);
	return ov.size();
}

struct command {
	std::string name;
	std::string header;

	virtual int options(po::options_description &desc) = 0;
	virtual int handle(std::vector<std::string> &arguments, po::variables_map &vm) = 0;
	
	virtual void print_help() {
		po::options_description desc;
		int pos = options(desc);
		int rem = remove_positional(desc, pos);
		if (rem) { // Are there any non-positional options?
			std::cerr << name << ":" << std::endl;
			std::cerr << desc << std::endl;
		}
	}
};

struct apply_command : command {

	apply_command() {
		name = "apply";
		header = "apply <before_tree> <patch_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("keep-backup,k", po::bool_switch()->default_value(false), "keep backup")
			("before", po::value<std::string>()->required(), "before tree")
			("patch", po::value<std::string>()->required(), "path to patch file");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("before", 1);
		pos.add("patch", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return apply(
			vm["before"].as<std::string>(),
			vm["patch"].as<std::string>(),
			vm["keep-backup"].as<bool>());
	}
};

struct create_command : command {

	create_command() {
		name = "create";
		header = "create <before_tree> <after_tree> <patch_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("cache,c", po::value<std::string>(), "location for cache")
			("threads,t", po::value<unsigned int>()->default_value(std::max(1u, std::thread::hardware_concurrency())), "number of threads to use")
			("memory,m", po::value<int>()->default_value(-1), "memory limit")
			("lzma-preset,l", po::value<unsigned int>()->default_value(2), "lzma compression preset")
			("require-exact-patch-target", po::value<bool>()->default_value(true), "patch target (directory) has to match patch source directory exactly (otherwise, allows other files in target directory when applying patch); creates slightly smaller patch files when enabled")
			("before", po::value<std::string>()->required(), "before tree (initial tree state)")
			("after", po::value<std::string>()->required(), "after tree (state to create after applying patch)")
			("patch", po::value<std::string>()->required(), "path to patch file being created");

		return 3;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);
		
		po::positional_options_description pos;
		
		pos.add("before", 1);
		pos.add("after", 1);
		pos.add("patch", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		boost::optional<path> cache;
		if (vm.count("cache"))
			cache = vm["cache"].as<std::string>();

		return create(
			vm["before"].as<std::string>(),
			vm["after"].as<std::string>(),
			vm["patch"].as<std::string>(),
			vm["threads"].as<unsigned int>(), 
			vm["memory"].as<int>(), 
			cache,
			vm["lzma-preset"].as<unsigned int>(),
			vm["require-exact-patch-target"].as<bool>());
	}
};

struct keypair_command : command {

	keypair_command() {
		name = "keypair";
		header = "keypair <secret_key_file> <public_key_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("secret_key", po::value<std::string>()->required(), "secret key file")
			("public_key", po::value<std::string>()->required(), "public key file");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("secret_key", 1);
		pos.add("public_key", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return keypair(
			vm["secret_key"].as<std::string>(),
			vm["public_key"].as<std::string>());
	}
};

struct sign_command : command {

	sign_command() {
		name = "sign";
		header = "sign <secret_key_file> <file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("secret_key", po::value<std::string>()->required(), "secret key file")
			("file", po::value<std::string>()->required(), "file to sign");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("secret_key", 1);
		pos.add("file", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return sign(
			vm["secret_key"].as<std::string>(),
			vm["file"].as<std::string>());
	}
};

struct verify_command : command {

	verify_command() {
		name = "verify";
		header = "verify <public_key_file> <file> <signature>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("public_key", po::value<std::string>()->required(), "public key file")
			("file", po::value<std::string>()->required(), "signed file to verify")
			("signature", po::value<std::string>()->required(), "signature");

		return 3;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("public_key", 1);
		pos.add("file", 1);
		pos.add("signature", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return verify(
			vm["public_key"].as<std::string>(),
			vm["file"].as<std::string>(),
			vm["signature"].as<std::string>());
	}
};

int show_help(int result, std::string &bn, po::options_description &desc, std::map<std::string, command*> commands) {

	remove_positional(desc, 2);

	if (result == 1) {
		std::cerr << "usage: " << bn << " <command> <args>" << std::endl;
		std::cerr << "Commands:" << std::endl;
		std::cerr << "  help" << std::endl;
		for (auto &i : commands) {
			std::cerr << "  " << i.second->header << std::endl;
		}
		std::cerr << std::endl;
		std::cerr << desc << std::endl;
		for (auto &i : commands) {
			i.second->print_help();
		}
	}

	return result;
}

int main(int argc, const char *argv[])
{
	
	std::string bn = basename(path(argv[0]));

	apply_command apply_cmd;
	create_command create_cmd;
	keypair_command keypair_cmd;
	sign_command sign_cmd;
	verify_command verify_cmd;

	std::map<std::string, command*> commands = {
			{ apply_cmd.name, &apply_cmd },
			{ create_cmd.name, &create_cmd },
			{ keypair_cmd.name, &keypair_cmd },
			{ sign_cmd.name, &sign_cmd },
			{ verify_cmd.name, &verify_cmd },
	};
	
	int result = 0;

	po::options_description op_desc("Options");
	op_desc.add_options()
		("verbose,v", po::bool_switch()->default_value(false), "enable verbose execution")
		("command", po::value<std::string>()->default_value("help"), "command to execute")
		("arguments", po::value<std::vector<std::string> >(), "arguments for command");


	po::positional_options_description pos_desc;
	pos_desc.add("command", 1);
	pos_desc.add("arguments", -1);

	po::variables_map vm;
	
	try {
		auto p = po::command_line_parser(argc, argv)
			.options(op_desc)
			.positional(pos_desc)
			.allow_unregistered()
			.run();

		po::store(p, vm);
		po::notify(vm);

		std::string cmd_string = vm["command"].as<std::string>();

		if (cmd_string == "help") {
			return show_help(1, bn, op_desc, commands);
		}

		auto cmd = commands.find(cmd_string);
		if (cmd == end(commands)) {
			throw po::invalid_option_value(cmd_string);
		}

		verbose = vm["verbose"].as<bool>();

		std::vector<std::string> args = po::collect_unrecognized(p.options, po::include_positional);
		args.erase(args.begin());

		result = cmd->second->handle(args, vm);
		
	}
	catch (po::error &e) {
		std::cerr << "error: " << e.what() << std::endl << std::endl;
		result = 1;
	}

	return show_help(result, bn, op_desc, commands);
}

int verify(const path &public_key_path, const path &file_path, const std::string &signature)
{
	if (!exists(public_key_path)) {
		std::cerr << "error: <public_key_file> '" << public_key_path.generic_string() << "' does not exist\n";
		return 2;
	}

	if (!exists(file_path)) {
		std::cerr << "error: <file> '" << file_path.generic_string() << "' does not exist\n";
		return 2;
	}

	std::vector<char> public_key_bytes;
	sporkel_util::get_file_contents(public_key_path, file_size(public_key_path), public_key_bytes);
	sporkel::public_key_ptr pk;
	pk.reset(sporkel_public_key_from_hex(public_key_bytes.data(), public_key_bytes.size()));
	if (!pk)
		return 2;

	sporkel::signature_ptr sig;
	sig.reset(sporkel_signature_from_hex(signature.data(), signature.length()));
	if (!sig)
		return 2;

	std::vector<uint8_t> data_bytes;
	sporkel_util::get_file_contents(file_path, file_size(file_path), data_bytes);

	if (!sporkel_verify(pk, sig, data_bytes.data(), data_bytes.size())) {
		std::cerr << "'" << file_path.generic_string() << "' verification failed\n";
		return 2;
	}

	std::cout << '\'' << file_path.generic_string() << "' verified\n";
	return 0;
}

int sign(const path &secret_key_path, const path &file_path)
{
	if (!exists(secret_key_path)) {
		std::cerr << "error: <secret_key_file> '" << secret_key_path.generic_string() << "' does not exist" << std::endl;
		return 2;
	}

	if (!exists(file_path)) {
		std::cerr << "error: <file> '" << file_path.generic_string() << "' does not exist" << std::endl;
		return 2;
	}

	std::vector<char> secret_key_bytes;
	sporkel_util::get_file_contents(secret_key_path, file_size(secret_key_path),
			secret_key_bytes);
	sporkel::secret_key_ptr sk;
	sk.reset(sporkel_secret_key_from_hex(secret_key_bytes.data(), secret_key_bytes.size()));
	if (!sk)
		return 3;

	std::vector<uint8_t> data_bytes;
	sporkel_util::get_file_contents(file_path, file_size(file_path), data_bytes);
	sporkel::signature_ptr sig;
	sig.reset(sporkel_sign(sk, data_bytes.data(), data_bytes.size()));
	if (!sig)
		return 3;

	printf("%s\n", sporkel_signature_hex(sig));
	return 0;
}

int keypair(const path &secret_key_path, const path &public_key_path)
{
	if (exists(secret_key_path)) {
		std::cerr << "error: <secret_key_path> '" << secret_key_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	if (exists(public_key_path)) {
		std::cerr << "error: <public_key_path> '" << public_key_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	sporkel::keypair_ptr pair;
	pair.reset(sporkel_keypair_create());

	printf("generating public and secret key...\n");

	auto sec = sporkel_keypair_secret_key(pair);
	auto pub = sporkel_keypair_public_key(pair);

	const char *sk = sporkel_secret_key_hex(sec);
	const char *pk = sporkel_public_key_hex(pub);

	sporkel_util::set_file_contents(secret_key_path, sk, strlen(sk));
	sporkel_util::set_file_contents(public_key_path, pk, strlen(pk));

	return 0;
}

static void sporkel_log(void*, sporkel_log_level level, const char *message)
{
	const char *level_string;

	if (!verbose && level <= SPORKEL_INFO)
		return;

	switch(level) {
		case SPORKEL_DEBUG: level_string = "debug: "; break;
		case SPORKEL_INFO: level_string = ""; break;
		case SPORKEL_WARNING: level_string = "warning: "; break;
		case SPORKEL_ERROR: level_string = "error: "; break;
	}

	if (level == SPORKEL_ERROR)
		std::cerr << level_string << message << std::endl;
	else
		std::cout << level_string << message << std::endl;
}

int create(const path &before_path, const path &after_path, const path &patch_path,
		unsigned int num_threads, unsigned int memory_limit, const boost::optional<path> &cache_path,
		unsigned int lzma_preset, bool require_exact_patch_target)
{

	if (!is_directory(before_path)) {
		std::cerr << "error: <before_tree> '" << before_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (!is_directory(after_path)) {
		std::cerr << "error: <after_tree> option '" << after_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (exists(patch_path)) {
		std::cerr << "error: <patch_file> '" << patch_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	if (cache_path && !is_directory(cache_path.get())) {
		std::cerr << "error: [cache_dir] '" << cache_path.get().generic_string() << "' is not a directory" << std::endl;
		return 3;
	}

	sporkel_callback_t cb {
		nullptr,
		nullptr,
		sporkel_log,
		nullptr
	};

	if (!sporkel_patch_create(before_path.generic_string().c_str(), after_path.generic_string().c_str(),
				patch_path.generic_string().c_str(), num_threads, memory_limit,
				cache_path ? cache_path->generic_string().c_str() : nullptr, lzma_preset,
				require_exact_patch_target,
				&cb))
		return 3;

	return 0;
}

static path get_valid_backup_path(path p)
{
	namespace fs = boost::filesystem;
	while (!p.empty()) {
		if (p.filename() == fs::detail::dot_path() ||
		    p.filename() == fs::detail::dot_dot_path()) {
			if (p.has_parent_path())
				p = p.parent_path();
			continue;
		} else {
			return p.parent_path() / (p.filename().string() + "_backup");
		}
	}
	return path("_backup");
}

int apply(const path &before_path, const path &patch_path, bool keep_backup)
{
	if (!is_directory(before_path)) {
		std::cerr << "error: <before_tree> '" << before_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (!exists(patch_path) || !is_regular_file(patch_path)) {
		std::cerr << "error: <patch_file> '" << patch_path.generic_string() << "' does not exist or not a file" << std::endl;
		return 2;
	}

	sporkel::tmp_dir_ptr tmp_dir(sporkel_tmp_dir_create());

	sporkel_callback_t cb {
		nullptr,
		nullptr,
		sporkel_log,
		nullptr
	};

	std::cout << "applying patch " << patch_path << " to " << before_path << std::endl;

	if (!sporkel_patch_apply(before_path.generic_string().c_str(), patch_path.generic_string().c_str(),
			sporkel_tmp_dir_path(tmp_dir), false, &cb))
		return 2;

	boost::system::error_code err;

	path tmp_path(sporkel_tmp_dir_path(tmp_dir));
	path backup_path(get_valid_backup_path(before_path));

	DEFER {
		std::cout << "removing temporary path " << tmp_path << std::endl;
		remove_all(tmp_path);
	};

	if (exists(backup_path)) {
		std::cerr << "error: backup path " << backup_path << " exists" << std::endl;
		return 2;
	}

	rename(before_path, backup_path, err);

	if (err.value() != boost::system::errc::success) {
		std::cerr << "error: failed to rename " << before_path << " to " << backup_path << std::endl;
		return 2;
	}

	DEFER {
		if (!keep_backup) {
			std::cout << "removing backup path " << backup_path << std::endl;
			remove_all(backup_path);
		}
	};

	if (!sporkel_util::copy_directory_recursive(tmp_path, before_path)) {
		std::cerr << "error: failed to copy " << tmp_path << " to " << before_path << std::endl;
		std::cout << "removing failed copy of " << before_path << std::endl;
		remove_all(before_path);
		std::cout << "restoring backup from " << backup_path << " to " << before_path << std::endl;
		err.clear();
		rename(backup_path, before_path, err);
		if (err.value() != boost::system::errc::success) {
			std::cerr << "error: failed to copy backup " << backup_path << " to " << before_path << std::endl;
		}
		return 2;
	}

	return 0;
}
