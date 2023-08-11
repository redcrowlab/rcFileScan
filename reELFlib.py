############################################################################################################
# Red Crow Lab - http://www.redcrowlab.com 
# Library for parsing ELF files and extracting useful information as well as basic vulnerability triage.
# reELFlib.py
############################################################################################################
import os
import hashlib
import math
import elftools.elf.elffile as ELFFile
import elftools.elf.dynamic as dynamic
import elftools.elf.relocation as relocation
import elftools.elf.sections as sections
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_64, CS_MODE_ARM, CS_MODE_32
from elftools.elf.constants import SH_FLAGS
from elftools.elf.sections import SymbolTableSection
import subprocess
import shlex
import re
import datetime
from elftools.elf.dynamic import DynamicSection


#####################################################
# Parses an ELF file and attempts to extract security
# significant information
class ELFParser:

	def __init__(self, file_path):
		self.file_path = file_path
		self._open_file()
		self._process_sections()

	def _open_file(self):
		self.file = open(self.file_path, 'rb')
		self.elf_file = ELFFile.ELFFile(self.file)

	def _close_file(self):
		if self.file:
			self.file.close()

	def __del__(self):
		self._close_file()

	def _process_sections(self):
		self.dynamic_section = None
		self.plt_reloc_section = None
		self.symtab_section = None

		for section in self.elf_file.iter_sections():
			if isinstance(section, dynamic.DynamicSection):
				self.dynamic_section = section
			if isinstance(section, relocation.RelocationSection) and section.is_RELA():
				self.plt_reloc_section = section
			if isinstance(section, sections.SymbolTableSection):
				self.symtab_section = section


#####################################################
# Get basic information about the binary such as class, machine, entrypoint
def getBinInfo(file_path):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		class_info = "ELF64" if elf_file.elfclass == 64 else "ELF32"
		data_info = "2's complement, little endian" if elf_file.little_endian else "2's complement, big endian"
		machine_info = elf_file.get_machine_arch()
		entry_point = hex(elf_file.header['e_entry'])

		info = {
			"Class": class_info,
			"Data": data_info,
			"Machine": machine_info,
			"Entry point address": entry_point
		}

	return(info)


#####################################################
# Return the size of the file
def getFileSize(file_path):
	try:
		file_size = os.path.getsize(file_path)
		return(file_size)
	except OSError as error:
		print(f"Error: {error}")
		return(None)


#####################################################
# Return the type of the file
def getFileType(file_path):
	try:
		with open(file_path, 'rb') as f:
			elf_file = ELFFile.ELFFile(f)
			file_type = elf_file.header.e_type
			machine = elf_file.header.e_machine

			if file_type == 'ET_EXEC':
				type_str = 'executable'
			elif file_type == 'ET_DYN':
				type_str = 'relocatable';
			else:
				type_str = 'unknown'

			if machine == 'EM_X86_64':
				arch_str = 'x86-64'
			elif machine == 'EM_386':
				arch_str = 'x86'
			elif machine == 'EM_ARM':
				arch_str = 'ARM'
			else:
				arch_str = 'unknown'

			return(f"{type_str} ({arch_str})")
	except Exception as error:
		print(f"Error:{error}")
		return(None)


#####################################################
# Get and return system file type 
def getSysFileType(file_path):
	# Check if 'file' command exists
	file_exists = subprocess.run(['which', 'file'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if file_exists.returncode != 0:
		print("Error: 'file' command not found.")
		return(None)

	# Run 'file' command
	command = f"file -b {shlex.quote(file_path)}"
	result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if result.returncode != 0:
		print(f"Error: {result.stderr.decode().strip()}")
		return(None)

	# Parse output
	output = result.stdout.decode().strip()
	build_id = None
	remaining_results = output

	if ', BuildID[' in output:
		parts = output.split(', BuildID[')
		build_id = parts[1].split(']')[0] if ']' in parts[1] else None
		remaining_results = parts[0]

	return(build_id, remaining_results)


#####################################################
# Return the md5 and sha256 checksums of the file 
def getCheckSums(file_path):
	try:
		with open(file_path, 'rb') as f:
			file_data = f.read()

		md5sum = hashlib.md5(file_data).hexdigest()
		sha256sum = hashlib.sha256(file_data).hexdigest()

		return(md5sum, sha256sum)
	except Exception as error:
		print(f"Error: {error}")
		return(None, None)


#####################################################
# Return the number of imports in the file
def countImports(elf_parser):
	imports = set()
	elf_file = elf_parser.elf_file
	for section in elf_file.iter_sections():
		if isinstance(section, RelocationSection) and section.is_RELA():
			symtab = elf_file.get_section(section['sh_link'])
			for rel in section.iter_relocations():
				symbol = symtab.get_symbol(rel['r_info_sym'])
				if symbol['st_shndx'] == 'SHN_UNDEF':
					name = symbol.name
					if name:
						imports.add(name)
	return len(imports)


#####################################################
# Return the file imports 
def getImports(file_path):
	imports = []
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)  # Note the change here
		for section in elf_file.iter_sections():
			if isinstance(section, RelocationSection) and section.is_RELA():
				symtab = elf_file.get_section(section['sh_link'])
				for rel in section.iter_relocations():
					symbol = symtab.get_symbol(rel['r_info_sym'])
					if symbol['st_shndx'] == 'SHN_UNDEF':
						name = symbol.name
						if name:
							imports.append(name)
	return(imports)


#####################################################
# Return the number of exports 
def countExports(elf_parser):
	if elf_parser.symtab_section is None:
		return None

	export_count = 0
	for symbol in elf_parser.symtab_section.iter_symbols():
		if symbol['st_info']['bind'] == 'STB_GLOBAL' and symbol['st_shndx'] != 'SHN_UNDEF':
			export_count += 1

	return(export_count)


#####################################################
# Return the exports in the file
def getExports(elf_parser):
	exports = []
	if elf_parser.symtab_section is None:
		return exports

	for symbol in elf_parser.symtab_section.iter_symbols():
		if symbol['st_info']['bind'] == 'STB_GLOBAL' and symbol['st_shndx'] != 'SHN_UNDEF':
			name = symbol.name
			if name:
				exports.append(name)

	return(exports)


#####################################################
# Return a list of the file security options such as 
# ASLR, DEP, NX
def getSECopts(elf_parser):
	sec_opts = {
		"RELRO": False,
		"Stack Protection": False,
		"NX": False,
		"ASLR": False,
		"DEP": False,
		"PIE": False
	}

	# Check for RELRO
	for segment in elf_parser.elf_file.iter_segments():
		if segment['p_type'] == 'PT_GNU_RELRO':
			sec_opts["RELRO"] = True

	# Check for Stack Protection
	for symbol in elf_parser.symtab_section.iter_symbols():
		if symbol.name == '__stack_chk_fail':
			sec_opts["Stack Protection"] = True

	# Check for NX and DEP
	for segment in elf_parser.elf_file.iter_segments():
		if segment['p_type'] == 'PT_GNU_STACK':
			if segment['p_flags'] & 0x1 == 0:
				sec_opts["NX"] = True
				sec_opts["DEP"] = True

	# Check for ASLR and PIE
	if elf_parser.elf_file['e_type'] == 'ET_DYN':
		has_interpreter = any(seg['p_type'] == 'PT_INTERP' for seg in elf_parser.elf_file.iter_segments())
		if not has_interpreter:
			sec_opts["ASLR"] = True
			sec_opts["PIE"] = True

	return(sec_opts)


#####################################################
# Determine what dependencies the binary has
def getDependencies(elf_parser):
	dependencies = []
	elf_file = elf_parser.elf_file
	for section in elf_file.iter_sections():
		if isinstance(section, DynamicSection):
			for tag in section.iter_tags():
				if tag.entry.d_tag == 'DT_NEEDED':
					dependencies.append(tag.needed)
	return(dependencies)


#####################################################
# Return the compile data of the file
def getCompileDate(elf_parser):
	byteorder = 'little' if elf_parser.elf_file.little_endian else 'big'

	for section in elf_parser.elf_file.iter_sections():

		if section.name == '.note.gnu.build-id':
			timestamp_bytes = section.data()[:4]
			timestamp = int.from_bytes(timestamp_bytes, byteorder=byteorder)
			compile_date = datetime.datetime.fromtimestamp(timestamp)
			return(compile_date)
		
		return(None)
	

#####################################################
# Get Prelink Date
def getPrelinkedTime(file_path):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)  # Note the change here
		for section in elf_file.iter_sections():
			if section['sh_type'] == 'SHT_NOTE':
				for note in section.iter_notes():
					if note['n_type'] == 'NT_GNU_PRELINKED':
						timestamp = int(note['n_desc'])
						link_time = datetime.datetime.fromtimestamp(timestamp)
						return link_time
	return(None)


#####################################################
# Return the strings in the file as a list
def getStrings(file_path, min_length=3):
	with open(file_path, 'rb') as f:
		data =f.read()

	pattern = f"[A-Za-z0-9/\-:.,_$%'()[\]<> ]{{{min_length},}}"
	result = re.findall(pattern, data.decode('ISO-8859-1'))

	return(result)


#####################################################
# Return the entropy of the file
def getEntropy(file_path):
	byte_counts = [0] * 256
	total_bytes = 0

	with open(file_path, 'rb') as f:
		for byte in iter(lambda: f.read(1), b''):
			byte_counts[ord(byte)] += 1
			total_bytes += 1

	entropy = 0
	for count in byte_counts:
		if count > 0:
			probability = count / total_bytes
			entropy += probability * math.log2(probability)

	return(-entropy)


#####################################################
# Count the number of sections in the file
def countSections(elf_parser):
	return len(list(elf_parser.elf_file.iter_sections()))


#####################################################
# Return the sections of the file
def getSections(elf_parser):
	sections = []
	for section in elf_parser.elf_file.iter_sections():
		sec_info = {
			"name": section.name,
			"type": section['sh_type'],
			"flags": section['sh_flags'],
			"address": hex(section['sh_addr']),
			"offset": hex(section['sh_offset']),
			"size": section['sh_size']
		}
		sections.append(sec_info)
	return(sections)


#####################################################
# Return the number of headers in the file
def countHeaders(file_path):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		header_count = len(list(elf_file.iter_segments()))
	return(header_count)


#####################################################
# Return the file headers
def getHeaders(file_path):
	header_names = []
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for segment in elf_file.iter_segments():
			header_names.append(segment.header['p_type'])
	return ", ".join(header_names)


#####################################################
# Return the any syscalls identified in the file. Needs work.
def getSyscalls(file_path):
	syscalls = []

	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		text_section = elf_file.get_section_by_name('.text')
		if not text_section:
			return syscalls

		code = text_section.data()
		address = text_section['sh_addr']

		# Determine the architecture and mode
		arch = elf_file.get_machine_arch()
		if arch == 'x64':
			cs_arch = CS_ARCH_X86
			cs_mode = CS_MODE_64
		elif arch == 'x86':
			cs_arch = CS_ARCH_X86
			cs_mode = CS_MODE_32
		elif arch == 'ARM':
			cs_arch = CS_ARCH_ARM
			cs_mode = CS_MODE_ARM
		else:
			print(f"Unsupported architecture: {arch}")
			return syscalls

		md = Cs(cs_arch, cs_mode)
		for instruction in md.disasm(code, address):
			if instruction.mnemonic == 'syscall' or (arch == 'ARM' and instruction.mnemonic == 'svc'):
				syscalls.append(instruction.address)

	return(syscalls)


#####################################################
# Attempt to identify uses of commonly vulnerable API calls by searching symbol table
# Doesn't work well if binary is stripped or optimized
def findBadCalls(file_path):
	vulnerable_functions = [
		"strcpy", "strcat", "sprintf", "gets", "memcpy", "memset",
		"fopen", "tmpfile", "mktemp", "printf", "fprintf", "snprintf",
		"malloc", "realloc", "system", "popen", "gethostbyname",
		"asctime", "ctime", "getwd", "index", "bcmp", "bcopy", "bzero",
		"ecvt", "fcvt", "gcvt", "readdir_r", "usleep", "vfork", 
		"swab", "ualarm", "ftime"
		# Add more functions as needed
	]

	found_functions = []

	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for section in elf_file.iter_sections():
			if section['sh_type'] == 'SHT_SYMTAB' or section['sh_type'] == 'SHT_DYNSYM':
				for symbol in section.iter_symbols():
					if symbol.name in vulnerable_functions:
						found_functions.append(symbol.name)

	return(found_functions)


#####################################################
# Look for unusual or insecure permissions on sections, 
# such as writable .text sections or executable .data sections.
# 'W' (write), 'A' (allocate), and 'X' (execute)
def checkSectionPerms(file_path):
	permissions = []
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for section in elf_file.iter_sections():
			perm_flags = []
			flags = section['sh_flags']
			if flags & SH_FLAGS.SHF_WRITE:
				perm_flags.append('W')
			if flags & SH_FLAGS.SHF_ALLOC:
				perm_flags.append('A')
			if flags & SH_FLAGS.SHF_EXECINSTR:
				perm_flags.append('X')
			perm_str = ''.join(perm_flags) or 'None'
			note = ''
			if 'W' in perm_str and 'X' in perm_str:
				note = ' (Potential Vuln: W & E perms)'
			permissions.append((section.name, perm_str, note))
	return(permissions)


#####################################################
# Check for the use of dynamic loading functions like dlopen, 
# which might indicate potential risks related to loading untrusted code at runtime.
def checkDynamicLoading(file_path):
	dynamic_loading_functions = ['dlopen', 'dlsym', 'dlclose', 'dlerror']
	found_functions = []

	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for section in elf_file.iter_sections():
			if isinstance(section, SymbolTableSection):
				for symbol in section.iter_symbols():
					if symbol.name in dynamic_loading_functions:
						found_functions.append(symbol.name)

	return(found_functions)


#####################################################
# Search the binary for patterns that might indicate hardcoded passwords, 
# keys, or other sensitive information.
def checkHardcodedStrings():
	sensitive_patterns = [
		r'password\s*=\s*["\'].*["\']',
		r'secret\s*=\s*["\'].*["\']',
		r'key\s*=\s*["\'].*["\']',
		r'pass\s*=\s*["\'].*["\']',
		r'api\s*=\s*["\'].*["\']',
		r'token\s*=\s*["\'].*["\']'
	]
	found_strings = []

	with open(file_path, 'rb') as f:
		file_content = f.read().decode('ISO-8859-1')  # Decoding to handle non-UTF-8 characters
		for pattern in sensitive_patterns:
			matches = re.findall(pattern, file_content, re.IGNORECASE)
			found_strings.extend(matches)

	return(found_strings)


#####################################################
# Check for the presence of CFI protections, which can mitigate control flow hijacking attacks.
# Unclear if this is really working
def checkCFI(file_path):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)  # Updated line

		# Check for the presence of .eh_frame_hdr section
		eh_frame_hdr = elf_file.get_section_by_name('.eh_frame_hdr')
		if eh_frame_hdr is None:
			return False

		# Check for the presence of PT_GNU_EH_FRAME segment
		for segment in elf_file.iter_segments():
			if segment['p_type'] == 'PT_GNU_EH_FRAME':
				return True

	return(False)


#####################################################
# Look for the presence of stack canaries, which can help detect stack buffer overflows.
def checkStackCanaries(file_path):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for section in elf_file.iter_sections():
			if section['sh_type'] == 'SHT_SYMTAB' or section['sh_type'] == 'SHT_DYNSYM':
				for symbol in section.iter_symbols():
					if symbol.name == '__stack_chk_fail':
						return(True)
	return(False)


#####################################################
# Check for the use of weak or outdated cryptographic functions, algorithms, or key sizes.
def checkWeakCrypto(file_path):
	weak_crypto_functions = [
		"MD4_Init", "MD4_Update", "MD4_Final",
		"MD5_Init", "MD5_Update", "MD5_Final",
		"RC4_set_key", "RC4",
		"DES_set_key", "DES_ecb_encrypt",
		"SHA1_Init", "SHA1_Update", "SHA1_Final",
		"DES_set_key", "DES_ecb_encrypt", "DES_ncbc_encrypt",
		"RC2_set_key", "RC2_ecb_encrypt",
		"RC4_set_key", "RC4",		
		"rand", "random",
		#"RSA_generate_key", # Check for key sizes in the context
		#"DH_generate_key",  
		#"crypt", # Check for weak salts or algorithms in the context	
	]
		
	found_weak_crypto = []

	with open(file_path, 'rb') as f:
		elf_file = ELFFile.ELFFile(f)
		for section in elf_file.iter_sections():
			if section['sh_type'] == 'SHT_SYMTAB' or section['sh_type'] == 'SHT_DYNSYM':
				for symbol in section.iter_symbols():
					if symbol.name in weak_crypto_functions:
						found_weak_crypto.append(symbol.name)

	return(found_weak_crypto)


#####################################################
# Look for patterns that might indicate potential race conditions
def checkRaceCond():
	pass


#####################################################
# Check for insecure file operations that might lead to symlink attacks, 
# TOCTOU (Time of Check to Time of Use) vulnerabilities, etc.
def checkFileOps():
	pass



