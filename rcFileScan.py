##################################################################################################
# Red Crow Lab - http://www.redcrowlab.com 
# Tool for parsing files and extracting useful information as well as basic vulnerability triage.
# rcFileScan.py
##################################################################################################
import argparse
import reELFlib

####################################################
# Formats file size output
def format_file_size(size):
	for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
		if size < 1024.0:
			break
		size /= 1024.0
	return f"{size:.2f} {unit}"

####################################################
# Main
def main(args):
	if args.all:
		args.size = True
		args.type = True
		args.checksums = True
		args.count_imports = True
		args.strings = True
		args.compile_date = True
		args.linker_time = True
		args.imports = True
		args.count_exports = True
		args.exports = True
		args.sec_opts = True
		args.count_sections = True
		args.get_sections = True
		args.entropy = True
		args.syscalls = True
		args.find_badCalls = True
		args.count_headers = True
		args.list_headers = True
		args.bin_info = True
		args.permissions = True
		args.dynamic_loading = True
		args.cfi_check = True
		args.stack_canaries = True
		args.weak_crypto = True

	file_path = args.file
	elf_parser = reELFlib.ELFParser(file_path)

	if args.size:
		file_size = reELFlib.getFileSize(file_path)
		if file_size is not None:
			formatted_size = format_file_size(file_size)
			print(f"[* FILE SIZE *]: {formatted_size}")

	if args.type:
		file_type = reELFlib.getFileType(file_path)
		if file_type is not None:
			print(f"[* FILE TYPE *]: {file_type}")
		sys_file_type = reELFlib.getSysFileType(file_path)
		if sys_file_type is not None:
			print(f"[* SYSTEM FILE TYPE *]: {sys_file_type}")

	if args.checksums:
		md5sum, sha256sum = reELFlib.getCheckSums(file_path)
		if md5sum is not None and sha256sum is not None:
			print(f"[* MD5SUM *]: {md5sum}")
			print(f"[* SHA256SUM *]: {sha256sum}")

	if args.bin_info:
		bin_info = reELFlib.getBinInfo(file_path)
		for key, value in bin_info.items():
			print(f"[* {key.upper()} *]: {value}")

	if args.count_imports:
		import_count = reELFlib.countImports(elf_parser)
		if import_count is not None:
			print(f"[* IMPORTS COUNT *]: {import_count}")

	if args.imports:
		imports = reELFlib.getImports(file_path)
		if imports is not None:
			print(f"[* IMPORTS *]: {imports}")
			
	if args.strings:
		strings = reELFlib.getStrings(file_path)
		if strings is not None:
			print(f"[* STRINGS *]: {strings}")
	
	if args.compile_date:
		compileDate = reELFlib.getCompileDate(elf_parser)
		if compileDate is not None:
			print(f"[* COMPILE DATE ]*: {compileDate}")
	
	if args.linker_time:
		linkerDate = reELFlib.getPrelinkedTime(file_path)
		if linkerDate is not None:
			print(f"[* LINKER DATE *]: {linkerDate}")

	if args.count_exports:
		exportsCount = reELFlib.countExports(elf_parser)
		if exportsCount is not None:
			print(f"[* EXPORTS COUNT *]: {exportsCount}")

	if args.exports:
		exports = reELFlib.getExports(elf_parser)
		if exports is not None:
			print(f"[* EXPORTS *]: {exports}")
	
	if args.sec_opts:
		sec_opts = reELFlib.getSECopts(elf_parser)
		print("[* SECURITY OPTIONS *]:")
		for opt, enabled in sec_opts.items():
			print(f"{opt}: {'Enabled' if enabled else 'Disabled'}")

	if args.count_sections:
		section_count = reELFlib.countSections(elf_parser)
		print(f"[* NUMBER OF SECTIONS *]: {section_count}")

	if args.get_sections:
		sections = reELFlib.getSections(elf_parser)
		print("[* SECTIONS *]:")
		for sec in sections:
			print(f"{sec['name']}")
			# To get more detailed section information change the print to this:
			# print(f"{sec['name']}, Type: {sec['type']}, Flags: {sec['flags']}, Address: {sec['address']}, Offset: {sec['offset']}, Size: {sec['size']}")

	if args.entropy:
		entropy = reELFlib.getEntropy(file_path)
		print(f"[* ENTROPY *]: {entropy}")

	if args.syscalls:
		syscalls = reELFlib.getSyscalls(file_path)
		print(f"[* SYSCALLS *]: {syscalls}")
	
	if args.find_badCalls:
		badCalls = reELFlib.findBadCalls(file_path)
		print(f"[* BAD CALLS *]: {badCalls}")

	if args.count_headers:
		header_count = reELFlib.countHeaders(file_path)
		print(f"[* NUMBER OF HEADERS *]: {header_count}")

	if args.list_headers:
		headers = reELFlib.getHeaders(file_path)
		print(f"[* HEADERS *]: {headers}")
	
	if args.permissions:
		permissions = reELFlib.checkSectionPerms(file_path)
		print("[* SECTION PERMISSIONS *]:")
		for section, perms, note in permissions:
			print(f"{section}: {perms}{note}")

	if args.dynamic_loading:
		dynamic_loading = reELFlib.checkDynamicLoading(file_path)
		if dynamic_loading:
			print(f"Dynamic Loading Functions Found: {', '.join(dynamic_loading)}")
		else:
			print("No Dynamic Loading Functions Found.")

	# Unclear if this check is really working, more difficult to setup a test
	if args.cfi_check:
		if reELFlib.checkCFI(file_path):
			print("[* CFI CHECK *]: CFI Present.")
		else:
			print("[* CFI CHECK *]: CFI Not Present.")

	if args.stack_canaries:
		if reELFlib.checkStackCanaries(file_path):
			print("[* STACK CANARY CHECK *]: Present.")
		else:
			print("[* STACK CANARY CHECK *]: Not present.")

	if args.weak_crypto:
		weak_crypto = reELFlib.checkWeakCrypto(file_path)
		if weak_crypto:
			print(f"[* WEAK CRYPTO CHECK *]: Functions Found: {', '.join(weak_crypto)}")
		else:
			print("[* WEAK CRYPTO CHECK *]: Functions Found.")

##########################################################
# Parse command line arguments
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Process ELF files.")
	parser.add_argument("-a", "--all", help="Run all options.", action="store_true")
	parser.add_argument("file", help="Path to the ELF file.")
	parser.add_argument("-s", "--size", help="Get file size.", action="store_true")
	parser.add_argument("-t", "--type", help="Get file type.", action="store_true")
	parser.add_argument("-c", "--checksums", help="Get file checksums (MD5 and SHA256).", action="store_true")
	parser.add_argument("-i", "--count_imports", help="Count imported symbols.", action="store_true")
	parser.add_argument("-S", "--strings", help="Extract Strings from Binary.", action="store_true")
	parser.add_argument("-C", "--compile_date", help="Extract compile date from Binary.", action="store_true")
	parser.add_argument("-l", "--linker_time", help="Extract linker date from Binary.", action="store_true")
	parser.add_argument("-I", "--imports", help="Extract imports from Binary.", action="store_true")
	parser.add_argument("-e", "--count_exports", help="Count Number of Exports.", action="store_true")
	parser.add_argument("-E", "--exports", help="Extract exports from Binary.", action="store_true")
	parser.add_argument("-O", "--sec_opts", help="Check security-related compile options.", action="store_true")
	parser.add_argument("-x", "--count_sections", help="Count the number of sections.", action="store_true")
	parser.add_argument("-X", "--get_sections", help="Print the details of the sections.", action="store_true")
	parser.add_argument("-N", "--entropy", help="Calculate the entropy of the file.", action="store_true")
	parser.add_argument("-z", "--syscalls", help="Attempt to identify and list syscalls.", action="store_true")
	parser.add_argument("-b", "--find_badCalls", help="Attempt to identify vulnerable API calls.", action="store_true")
	parser.add_argument("-ch", "--count_headers", help="Count the number of headers.", action="store_true")
	parser.add_argument("-lh", "--list_headers", help="List the headers.", action="store_true")
	parser.add_argument("-bi", "--bin_info", help="Get binary information.", action="store_true")
	parser.add_argument("-p", "--permissions", help="List the permissions on sections.", action="store_true")
	parser.add_argument("-d", "--dynamic_loading", help="Check for dynamic loading functions.", action="store_true")
	parser.add_argument("-cf", "--cfi_check", help="Check for CFI protections.", action="store_true")
	parser.add_argument("-sc", "--stack_canaries", help="Check for stack canaries.", action="store_true")
	parser.add_argument("-w", "--weak_crypto", help="Check for weak cryptographic functions.", action="store_true")

	args = parser.parse_args()
	main(args)
