#include <algorithm>
#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <unordered_map>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void get_basename_lowercase(std::string &destination, const char *filename)
{
	destination = filename;
	size_t last_slash_index = destination.find_last_of("/\\");
	if (last_slash_index != std::string::npos) {
		destination = destination.substr(destination.find_last_of("/\\") + 1);
	}
	std::transform(destination.begin(), destination.end(), destination.begin(), std::tolower);
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		std::cout << "Usage: library_injection_patcher.exe <binary-file> <library-file>" << std::endl;
		return 0;
	}

	std::ifstream destination_file(argv[1], std::ios::in | std::ios::binary);
	if (!destination_file) {
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	std::ifstream import_file(argv[2], std::ios::in | std::ios::binary);
	if (!import_file) {
		std::cout << "Cannot open " << argv[2] << std::endl;
		return -1;
	}

	try {
		pe_base import_image(pe_factory::create_pe(import_file));

		//Проверим, есть ли экспорты у PE-файла
		if (!import_image.has_exports()) {
			std::cout << "Image " << argv[2] << " has no exports" << std::endl;
			return 0;
		}

		pe_base destination_image(pe_factory::create_pe(destination_file));
		imported_functions_list imports(get_imported_functions(destination_image));

		std::string import_basename, new_import_basename;
		get_basename_lowercase(new_import_basename, argv[2]);
		for (auto it = imports.begin(); it != imports.end(); ++it) {
			get_basename_lowercase(import_basename, it->get_name().c_str());
			if (import_basename == new_import_basename) {
				std::cout << "Image " << argv[2] << " is already imported" << std::endl;
				return -1;
			}
		}

		import_library imported_library;
		imported_library.set_name(argv[2]);
		destination_file.close();

		export_info import_info;
		const exported_functions_list exports = get_exported_functions(import_image, import_info);

		uint64_t iat_va_counter = 0;
		for (auto it = exports.begin(); it != exports.end(); ++it) {
			imported_function func;
			func.set_name(it->get_name());
			func.set_iat_va(++iat_va_counter);
			func.set_hint(it->get_ordinal() - import_info.get_ordinal_base());
			imported_library.add_import(func);
		}

		imports.push_back(imported_library);

		section new_imports;
		std::hash<std::string> import_hash;
		size_t import_hashcode = import_hash(std::string(argv[2]));
		char import_hash_string[20];
		sprintf_s(import_hash_string, "%016x", import_hashcode);
		new_imports.get_raw_data().resize(1);
		new_imports.set_name(import_hash_string);
		new_imports.readable(true).writeable(true);
		section &attached_section = destination_image.add_section(new_imports);

		import_rebuilder_settings settings(true, false);
		rebuild_imports(destination_image, imports, attached_section, settings);

		std::ofstream new_destination_file(argv[1], std::ios::out | std::ios::binary | std::ios::trunc);
		if (!new_destination_file) {
			std::cout << "Cannot create " << argv[1] << std::endl;
			return -1;
		}

		rebuild_pe(destination_image, new_destination_file);

		std::cout << "PE was rebuilt and saved to " << argv[1] << std::endl;
	} catch(const pe_exception &e) {
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
