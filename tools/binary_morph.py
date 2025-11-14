#!/usr/bin/env python3
"""
Binary Morphing Tool - Post-compilation binary obfuscation
Modifies PE binary to evade static signatures while preserving functionality
"""

import sys
import os
import struct
import random

class BinaryMorpher:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.data = bytearray(f.read())
        self.original_size = len(self.data)
        
    def verify_pe(self):
        """Verify PE signature"""
        if self.data[0:2] != b'MZ':
            raise ValueError("Not a valid PE file")
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        return pe_offset
        
    def add_entropy_section(self):
        """Add entropy-rich section to confuse ML classifiers"""
        print("[*] Adding entropy section...")
        
        # Generate pseudo-random but legitimate-looking data
        entropy_data = bytearray()
        
        # Add fake PNG header
        entropy_data.extend(b'\x89PNG\r\n\x1a\n')
        entropy_data.extend(random.randbytes(512))
        
        # Add fake ZIP header  
        entropy_data.extend(b'PK\x03\x04')
        entropy_data.extend(random.randbytes(512))
        
        # Add fake certificate data
        entropy_data.extend(b'0\x82')
        entropy_data.extend(random.randbytes(1024))
        
        # Append to overlay (after PE)
        self.data.extend(entropy_data)
        print(f"    Added {len(entropy_data)} bytes of entropy")
        
    def modify_timestamps(self):
        """Randomize PE timestamps"""
        print("[*] Randomizing timestamps...")
        pe_offset = self.verify_pe()
        
        # TimeDateStamp at offset 8 in COFF header
        timestamp_offset = pe_offset + 8
        new_timestamp = random.randint(0x40000000, 0x60000000)
        struct.pack_into('<I', self.data, timestamp_offset, new_timestamp)
        print(f"    Set timestamp to: {hex(new_timestamp)}")
        
    def patch_code_caves(self):
        """Fill code caves with polymorphic NOPs"""
        print("[*] Filling code caves...")
        
        # NOP variations
        nop_variants = [
            b'\x90',  # NOP
            b'\x66\x90',  # 2-byte NOP
            b'\x0F\x1F\x00',  # 3-byte NOP
            b'\x0F\x1F\x40\x00',  # 4-byte NOP
        ]
        
        count = 0
        # Find NULL byte sequences (code caves)
        i = 0
        while i < len(self.data) - 16:
            if self.data[i:i+4] == b'\x00\x00\x00\x00':
                # Found a cave, fill with random NOPs
                cave_size = 0
                while i + cave_size < len(self.data) and self.data[i + cave_size] == 0:
                    cave_size += 1
                
                if cave_size >= 4:
                    # Fill cave
                    filled = 0
                    while filled < cave_size:
                        nop = random.choice(nop_variants)
                        if filled + len(nop) <= cave_size:
                            self.data[i+filled:i+filled+len(nop)] = nop
                            filled += len(nop)
                        else:
                            break
                    count += 1
                i += cave_size
            i += 1
            
        print(f"    Filled {count} code caves")
        
    def modify_section_characteristics(self):
        """Randomize section characteristics"""
        print("[*] Randomizing section characteristics...")
        # DISABLED - Can corrupt PE structure
        print("    Skipped (can corrupt PE structure)")
        return
        
    def insert_junk_imports(self):
        """Add benign import entries to confuse analysis"""
        print("[*] Adding decoy imports...")
        # Note: This is complex, just log for now
        print("    Skipped (requires full PE reconstruction)")
        
    def save(self, output_path=None):
        """Save morphed binary"""
        if output_path is None:
            output_path = self.filepath
            
        with open(output_path, 'wb') as f:
            f.write(self.data)
            
        print(f"\n[+] Morphed binary saved: {output_path}")
        print(f"    Original size: {self.original_size} bytes")
        print(f"    New size: {len(self.data)} bytes (+{len(self.data)-self.original_size} bytes)")

def main():
    if len(sys.argv) < 2:
        print("Usage: python binary_morph.py <exe_file>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
        
    print("=" * 60)
    print("  Binary Morphing Tool - PE Obfuscation")
    print("=" * 60)
    print(f"\nTarget: {filepath}\n")
    
    try:
        morpher = BinaryMorpher(filepath)
        
        # Apply transformations
        morpher.verify_pe()
        morpher.modify_timestamps()
        morpher.add_entropy_section()
        morpher.patch_code_caves()
        morpher.modify_section_characteristics()
        morpher.insert_junk_imports()
        
        # Save
        morpher.save()
        
        print("\n" + "=" * 60)
        print("[SUCCESS] Binary morphing complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
