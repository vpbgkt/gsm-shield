#!/usr/bin/env python3
"""
Expiro Detection Tool - Phase 1
Purpose: Scan system for Expiro.EK infections without deletion
Output: Detailed report of infected files for analysis

Usage: python expiro_detector.py <directory>
"""

import os
import sys
import hashlib
import struct
from pathlib import Path
from datetime import datetime

try:
    import pefile
except ImportError:
    print("ERROR: pefile module not installed")
    print("Install with: pip install pefile")
    sys.exit(1)


class ExpiroDetector:
    """
    Detects Win32/Expiro file infector using multiple heuristics
    """
    
    # Known Expiro section names
    SUSPICIOUS_SECTIONS = [
        '.expiro', '.virus', '.packed', '.stub',
        'UPX0', 'UPX1', '.ndata', '.xdata'
    ]
    
    # High entropy threshold (encrypted/packed code)
    ENTROPY_THRESHOLD = 7.0
    
    # Typical size increase range
    MIN_SIZE_INCREASE = 40 * 1024  # 40 KB
    MAX_SIZE_INCREASE = 150 * 1024  # 150 KB
    
    def __init__(self):
        self.infected_files = []
        self.scan_count = 0
        self.error_count = 0
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0
        
        entropy = 0
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        data_len = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = float(count) / data_len
            entropy -= probability * (probability and __import__('math').log(probability, 2))
        
        return entropy
    
    def check_expiro_signatures(self, pe, filepath):
        """
        Check for Expiro infection indicators
        Returns: (is_infected, confidence, reasons)
        """
        reasons = []
        confidence = 0
        
        try:
            # Check 1: Suspicious section names
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                
                if any(sus in section_name.lower() for sus in ['.expiro', '.virus', '.packed']):
                    reasons.append(f"Suspicious section: {section_name}")
                    confidence += 30
                
                # Check 2: High entropy sections with execute permissions
                entropy = section.get_entropy()
                is_executable = section.Characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
                
                if entropy > self.ENTROPY_THRESHOLD and is_executable:
                    reasons.append(f"High entropy executable section: {section_name} (entropy: {entropy:.2f})")
                    confidence += 20
                
                # Check 3: Section size anomalies
                if section.SizeOfRawData > 0:
                    virtual_to_raw_ratio = section.Misc_VirtualSize / section.SizeOfRawData
                    if virtual_to_raw_ratio > 2.0 or virtual_to_raw_ratio < 0.5:
                        reasons.append(f"Suspicious section size ratio: {section_name}")
                        confidence += 10
            
            # Check 4: Unusual number of sections
            section_count = pe.FILE_HEADER.NumberOfSections
            if section_count > 8:
                reasons.append(f"Unusual section count: {section_count}")
                confidence += 15
            
            # Check 5: Entry point in unusual section
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = None
            for section in pe.sections:
                if section.VirtualAddress <= ep_rva < section.VirtualAddress + section.Misc_VirtualSize:
                    ep_section = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    break
            
            if ep_section and ep_section not in ['.text', 'CODE', '.code']:
                reasons.append(f"Entry point in unusual section: {ep_section}")
                confidence += 25
            
            # Check 6: TLS callback suspicious patterns
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                reasons.append("TLS callbacks present (potential infection vector)")
                confidence += 10
            
            # Check 7: Import table anomalies
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                suspicious_imports = ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread']
                found_suspicious = []
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode('utf-8', errors='ignore') in suspicious_imports:
                            found_suspicious.append(imp.name.decode('utf-8', errors='ignore'))
                
                if len(found_suspicious) >= 2:
                    reasons.append(f"Suspicious API imports: {', '.join(found_suspicious)}")
                    confidence += 15
            
        except Exception as e:
            reasons.append(f"Analysis error: {str(e)}")
            return False, 0, reasons
        
        is_infected = confidence >= 50
        return is_infected, confidence, reasons
    
    def scan_file(self, filepath):
        """
        Scan a single file for Expiro infection
        """
        self.scan_count += 1
        
        try:
            # Only scan PE files
            if not filepath.lower().endswith(('.exe', '.dll', '.sys')):
                return None
            
            # Parse PE file
            pe = pefile.PE(filepath, fast_load=True)
            pe.parse_data_directories()
            
            # Run detection checks
            is_infected, confidence, reasons = self.check_expiro_signatures(pe, filepath)
            
            if is_infected:
                file_size = os.path.getsize(filepath)
                file_hash = self.calculate_file_hash(filepath)
                
                detection = {
                    'path': filepath,
                    'size': file_size,
                    'confidence': confidence,
                    'reasons': reasons,
                    'sha256': file_hash,
                    'timestamp': datetime.now().isoformat(),
                    'sections': []
                }
                
                # Collect section info
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    detection['sections'].append({
                        'name': section_name,
                        'virtual_size': section.Misc_VirtualSize,
                        'raw_size': section.SizeOfRawData,
                        'entropy': section.get_entropy(),
                        'characteristics': hex(section.Characteristics)
                    })
                
                self.infected_files.append(detection)
                return detection
            
            pe.close()
            return None
            
        except pefile.PEFormatError:
            # Not a valid PE file, skip
            return None
        except Exception as e:
            self.error_count += 1
            print(f"  ERROR scanning {filepath}: {str(e)}")
            return None
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def scan_directory(self, directory, recursive=True):
        """
        Scan a directory for infected files
        """
        print(f"\n[*] Scanning: {directory}")
        print(f"[*] Recursive: {recursive}")
        print("-" * 60)
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    detection = self.scan_file(filepath)
                    
                    if detection:
                        print(f"\n🦠 INFECTED: {filepath}")
                        print(f"   Confidence: {detection['confidence']}%")
                        for reason in detection['reasons']:
                            print(f"   - {reason}")
                    
                    # Progress indicator
                    if self.scan_count % 100 == 0:
                        print(f"  [Progress: {self.scan_count} files scanned, {len(self.infected_files)} infected]", end='\r')
        else:
            for item in Path(directory).iterdir():
                if item.is_file():
                    detection = self.scan_file(str(item))
                    
                    if detection:
                        print(f"\n🦠 INFECTED: {item}")
                        print(f"   Confidence: {detection['confidence']}%")
                        for reason in detection['reasons']:
                            print(f"   - {reason}")
    
    def generate_report(self, output_file):
        """
        Generate detailed scan report
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("GSM SHIELD AV - EXPIRO DETECTION REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Files Scanned: {self.scan_count}\n")
            f.write(f"Infected Files: {len(self.infected_files)}\n")
            f.write(f"Errors: {self.error_count}\n")
            f.write("\n" + "=" * 80 + "\n\n")
            
            if not self.infected_files:
                f.write("No Expiro infections detected.\n")
            else:
                for idx, detection in enumerate(self.infected_files, 1):
                    f.write(f"\n[{idx}] INFECTED FILE\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"Path: {detection['path']}\n")
                    f.write(f"Size: {detection['size']:,} bytes\n")
                    f.write(f"SHA256: {detection['sha256']}\n")
                    f.write(f"Confidence: {detection['confidence']}%\n")
                    f.write(f"Detection Time: {detection['timestamp']}\n")
                    f.write("\nReasons:\n")
                    for reason in detection['reasons']:
                        f.write(f"  - {reason}\n")
                    
                    f.write("\nSection Analysis:\n")
                    for section in detection['sections']:
                        f.write(f"  [{section['name']}]\n")
                        f.write(f"    Virtual Size: {section['virtual_size']:,} bytes\n")
                        f.write(f"    Raw Size: {section['raw_size']:,} bytes\n")
                        f.write(f"    Entropy: {section['entropy']:.2f}\n")
                        f.write(f"    Characteristics: {section['characteristics']}\n")
                    
                    f.write("\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"\n[✓] Report saved to: {output_file}")


def main():
    """Main entry point"""
    print("=" * 60)
    print("GSM SHIELD AV - EXPIRO DETECTOR v1.0")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUsage: python expiro_detector.py <directory> [--no-recursive]")
        print("\nExample:")
        print("  python expiro_detector.py C:\\Windows\\System32")
        print("  python expiro_detector.py C:\\Program Files --no-recursive")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    recursive = '--no-recursive' not in sys.argv
    
    if not os.path.exists(target_dir):
        print(f"\nERROR: Directory not found: {target_dir}")
        sys.exit(1)
    
    # Create detector and scan
    detector = ExpiroDetector()
    detector.scan_directory(target_dir, recursive=recursive)
    
    # Generate report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f"research/logs/expiro_scan_{timestamp}.txt"
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    detector.generate_report(report_file)
    
    # Summary
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Files Scanned: {detector.scan_count}")
    print(f"Infections Found: {len(detector.infected_files)}")
    print(f"Errors: {detector.error_count}")
    print(f"Report: {report_file}")
    print("=" * 60)


if __name__ == '__main__':
    main()
