##################################################################################################
# Red Crow Lab - http://www.redcrowlab.com
# Tool for changing permisions on a ELF Binary file header section.
# rcSectionMangler.py
##################################################################################################

import argparse
from elftools.elf.elffile import ELFFile

############################################################
# Function that sets permissions on given file and section name.
def setPermissions(file_path, section_name, permissions):
	with open(file_path, 'rb') as f:
		elf_file = ELFFile(f)
		section = elf_file.get_section_by_name(section_name)
		if section is None:
			print(f"Section {section_name} not found in {file_path}.")
			return False

		# Get the section header
		shdr = section.header

		# Set the permissions
		shdr['sh_flags'] = 0
		if 'R' in permissions:
			shdr['sh_flags'] |= 0x4
		if 'W' in permissions:
			shdr['sh_flags'] |= 0x1
		if 'X' in permissions:
			shdr['sh_flags'] |= 0x2

		# Find the index of the section
		section_index = None
		for idx, sec in enumerate(elf_file.iter_sections()):
			if sec.name == section_name:
				section_index = idx
				break

		if section_index is None:
			print(f"Section {section_name} not found in {file_path}.")
			return False

		# Calculate the offset of the section header in the file
		sh_offset = elf_file.header.e_shoff + section_index * elf_file.header.e_shentsize

		# Convert the modified header to bytes
		shdr_bytes = elf_file.structs.Elf_Shdr.build(shdr)

		# Write the modified header back to the file
		with open(file_path, 'r+b') as f:
			f.seek(sh_offset)
			f.write(shdr_bytes)

	print(f"Permissions for {section_name} in {file_path} set to {permissions}.")
	return(True)


############################################################
# Main
def main():
	parser = argparse.ArgumentParser(description="Change section permissions in an ELF binary.")
	parser.add_argument("file_path", help="Path to the ELF file.")
	parser.add_argument("section_name", help="Name of the section to modify.")
	parser.add_argument("permissions", help="Permissions to set (e.g., 'RWX').")
	args = parser.parse_args()

	setPermissions(args.file_path, args.section_name, args.permissions)

if __name__ == "__main__":
	main()
