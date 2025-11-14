#!/usr/bin/env python3
"""
Source Code Obfuscation Tool
Obfuscates C/C++ source files with string encryption, control flow obfuscation, and more
"""

import os
import re
import random
import string
import sys
from pathlib import Path

class SourceObfuscator:
    def __init__(self):
        self.string_counter = 0
        self.encrypted_strings = []
        self.function_map = {}
        
    def generate_random_name(self, length=12):
        """Generate random identifier name"""
        first = random.choice(string.ascii_letters + '_')
        rest = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length-1))
        return first + rest
    
    def xor_encrypt_string(self, s):
        """XOR encrypt a string with a random key"""
        key = random.randint(1, 255)
        encrypted = [ord(c) ^ key for c in s]
        return encrypted, key
    
    def obfuscate_strings(self, content):
        """Replace string literals with encrypted versions"""
        # Find all string literals
        pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
        
        def replace_string(match):
            original = match.group(1)
            if len(original) == 0 or original.startswith('\\'):
                return match.group(0)  # Skip empty or escape sequences
            
            encrypted, key = self.xor_encrypt_string(original)
            var_name = f"_s{self.string_counter}"
            self.string_counter += 1
            
            # Create decryption code
            hex_bytes = ','.join([f'0x{b:02x}' for b in encrypted])
            decryption = f'([&](){{static char {var_name}[]={{{hex_bytes},0}};static bool _d=false;if(!_d){{for(int i=0;{var_name}[i];i++){var_name}[i]^=0x{key:02x};_d=true;}}return {var_name};}}))'
            
            return decryption
        
        return re.sub(pattern, replace_string, content)
    
    def add_junk_code(self, content):
        """Add junk code to confuse analysis"""
        junk_templates = [
            "volatile int _junk{0} = {1}; if(_junk{0} == {2}) {{ _junk{0} = {3}; }}",
            "static const char _dummy{0}[] = \"{4}\"; (void)_dummy{0};",
            "int _x{0} = {1}; _x{0} = (_x{0} * {2}) ^ {3};",
        ]
        
        lines = content.split('\n')
        new_lines = []
        
        for line in lines:
            new_lines.append(line)
            # Add junk after function opening braces
            if '{' in line and not line.strip().startswith('//'):
                if random.random() < 0.3:  # 30% chance
                    indent = len(line) - len(line.lstrip())
                    junk_idx = random.randint(0, 2)
                    junk_num = random.randint(1000, 9999)
                    vals = [random.randint(1, 100) for _ in range(4)]
                    rand_str = ''.join(random.choices(string.ascii_letters, k=8))
                    junk = junk_templates[junk_idx].format(junk_num, vals[0], vals[1], vals[2], rand_str)
                    new_lines.append(' ' * (indent + 4) + junk)
        
        return '\n'.join(new_lines)
    
    def obfuscate_control_flow(self, content):
        """Add control flow obfuscation"""
        # Add opaque predicates
        opaque_predicates = [
            "if((rand()&1)==2) {{ return; }}",  # Always false
            "if(((int*)&_dummy)[0]==0x12345678) {{ return; }}",  # Always false
        ]
        
        lines = content.split('\n')
        new_lines = []
        dummy_added = False
        
        for line in lines:
            # Add dummy variable at start of functions
            if '{' in line and ('(' in line or 'namespace' not in line):
                new_lines.append(line)
                if not dummy_added and random.random() < 0.2:
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(' ' * (indent + 4) + f"volatile int _dummy = {random.randint(1,100)};")
                    dummy_added = True
            else:
                new_lines.append(line)
        
        return '\n'.join(new_lines)
    
    def obfuscate_integers(self, content):
        """Obfuscate integer literals"""
        def replace_int(match):
            num = int(match.group(0))
            if abs(num) < 10 or num > 1000000:  # Skip small numbers and very large ones
                return match.group(0)
            
            # Use arithmetic expression instead of literal
            operations = [
                lambda n: f"({n//2}+{n-n//2})",
                lambda n: f"({n+5}-5)",
                lambda n: f"({n*2}/2)",
                lambda n: f"((({n//10})*10)+{n%10})" if n >= 10 else str(n),
            ]
            
            if random.random() < 0.3:  # 30% obfuscation rate
                op = random.choice(operations)
                return op(num)
            return match.group(0)
        
        # Only replace standalone integers, not in hex or strings
        pattern = r'\b([1-9]\d{2,})\b'
        return re.sub(pattern, replace_int, content)
    
    def process_file(self, filepath):
        """Process a single source file"""
        print(f"[*] Obfuscating: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        original_size = len(content)
        
        # Apply obfuscation techniques
        if filepath.endswith(('.cpp', '.c', '.h')):
            # String obfuscation
            content = self.obfuscate_strings(content)
            
            # Integer obfuscation
            content = self.obfuscate_integers(content)
            
            # Add junk code
            content = self.add_junk_code(content)
            
            # Control flow obfuscation
            content = self.obfuscate_control_flow(content)
        
        # Backup original
        backup_path = str(filepath) + '.bak'
        if not os.path.exists(backup_path):
            with open(backup_path, 'w', encoding='utf-8') as f:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as orig:
                    f.write(orig.read())
        
        # Write obfuscated version
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        new_size = len(content)
        print(f"    Size: {original_size} -> {new_size} bytes ({(new_size-original_size)/original_size*100:+.1f}%)")
        print(f"    Strings encrypted: {self.string_counter}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python obfuscate.py <source_directory>")
        sys.exit(1)
    
    src_dir = Path(sys.argv[1])
    if not src_dir.exists():
        print(f"Error: Directory {src_dir} does not exist")
        sys.exit(1)
    
    obfuscator = SourceObfuscator()
    
    # Find all C/C++ source files
    extensions = ['*.cpp', '*.c', '*.h']
    files_to_obfuscate = []
    
    for ext in extensions:
        files_to_obfuscate.extend(src_dir.glob(ext))
    
    print(f"\n[+] Found {len(files_to_obfuscate)} files to obfuscate")
    print("=" * 60)
    
    for filepath in files_to_obfuscate:
        # Skip already obfuscated files
        if '.bak' in str(filepath):
            continue
        
        # Skip certain files that shouldn't be obfuscated
        skip_files = ['reflective_loader.c', 'reflective_loader.h', 'sqlite3.c', 'sqlite3.h']
        if filepath.name in skip_files:
            print(f"[~] Skipping: {filepath.name} (excluded)")
            continue
        
        try:
            obfuscator.process_file(filepath)
        except Exception as e:
            print(f"[!] Error processing {filepath}: {e}")
    
    print("=" * 60)
    print(f"[+] Obfuscation complete!")
    print(f"[+] Original files backed up with .bak extension")
    print(f"\n[!] To restore original files, run:")
    print(f"    for file in {src_dir}/*.bak; do mv \"$file\" \"${{file%.bak}}\"; done")

if __name__ == '__main__':
    main()
