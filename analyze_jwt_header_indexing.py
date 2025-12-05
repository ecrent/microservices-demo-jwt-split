#!/usr/bin/env python3
"""
JWT Header HPACK Indexing Analysis (3-Header Format) - Version 2
Analyzes pcap files to determine how JWT headers are being indexed in HTTP/2 HPACK compression.

3-Header Format:
- x-jwt-header: Base64url encoded JWT header (constant: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9)
- x-jwt-payload: Raw JSON payload (not base64 encoded)
- x-jwt-sig: Base64url signature only

This version properly handles the tshark output by processing each header individually.
"""

import subprocess
import re
import json
from collections import defaultdict
from pathlib import Path
import hashlib

# Constants for identifying JWT header values
JWT_HEADER_CONSTANT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9'

class JWTHeaderAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        # 3-header format: x-jwt-header, x-jwt-payload, x-jwt-sig
        self.header_stats = {
            'x-jwt-header': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()},
            'x-jwt-payload': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()},
            'x-jwt-sig': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()}
        }
        self.total_frames = 0
        self.frames_with_jwt = 0
        self.unique_sessions = set()
        self.header_name_indexing = {
            'x-jwt-header': {'name_indexed': 0, 'name_literal': 0},
            'x-jwt-payload': {'name_indexed': 0, 'name_literal': 0},
            'x-jwt-sig': {'name_indexed': 0, 'name_literal': 0}
        }
        # Track actual byte transmission for savings calculation
        self.byte_tracking = {
            'x-jwt-header': {
                'literal_bytes_sent': 0,
                'indexed_references': 0,
                'first_occurrences': 0,
                'reused_from_table': 0,
                'potential_bytes': 0,
                'value_occurrences': {},
            },
            'x-jwt-payload': {
                'literal_bytes_sent': 0,
                'indexed_references': 0,
                'first_occurrences': 0,
                'reused_from_table': 0,
                'potential_bytes': 0,
                'value_occurrences': {},
            },
            'x-jwt-sig': {
                'literal_bytes_sent': 0,
                'indexed_references': 0,
                'first_occurrences': 0,
                'reused_from_table': 0,
                'potential_bytes': 0,
                'value_occurrences': {},
            }
        }
        
    def extract_headers_per_frame(self):
        """Extract HTTP/2 headers one per line with frame info"""
        print(f"Analyzing pcap file: {self.pcap_file}")
        print("Extracting HTTP/2 headers individually...")
        print("Looking for headers: x-jwt-header, x-jwt-payload, x-jwt-sig")
        
        # Use a different approach: get each header as a separate entry
        # This avoids the comma-separation issue
        cmd = [
            'tshark', '-r', self.pcap_file,
            '-d', 'tcp.port==7070,http2',
            '-Y', 'http2.header',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'http2.streamid', 
            '-e', 'http2.header.name',
            '-e', 'http2.header.value',
            '-e', 'http2.header.repr',
            '-E', 'separator=\t',
            '-E', 'occurrence=a'  # Show all occurrences
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            print(f"Error running tshark: {e}")
            return []
    
    def identify_header_type(self, header_name, header_value):
        """Identify the JWT header type from name or value pattern"""
        # If the name is known, use it
        if header_name in ['x-jwt-header', 'x-jwt-payload', 'x-jwt-sig']:
            return header_name
        
        # If name is <unknown> (indexed in HPACK), identify by value
        if header_name == '<unknown>' or not header_name:
            # x-jwt-header is always the constant
            if header_value == JWT_HEADER_CONSTANT:
                return 'x-jwt-header'
            # x-jwt-payload is raw JSON with session_id
            if header_value.startswith('{') and 'session_id' in header_value:
                return 'x-jwt-payload'
            # x-jwt-sig is a long base64url string
            if len(header_value) > 100 and not header_value.startswith('{') and '.' not in header_value:
                return 'x-jwt-sig'
        
        return None
    
    def analyze(self):
        """Run the full analysis"""
        lines = self.extract_headers_per_frame()
        
        print(f"Processing {len(lines)} lines of tshark output...")
        
        frames_with_jwt = set()
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split('\t')
            if len(parts) < 5:
                continue
            
            frame_num = parts[0]
            stream_id = parts[1]
            header_names_str = parts[2]
            header_values_str = parts[3]
            representations_str = parts[4] if len(parts) > 4 else ""
            
            # tshark with occurrence=a separates multiple values with commas
            # But we need to be smarter about parsing JSON payloads
            
            # Split header names (these don't contain commas)
            header_names = header_names_str.split(',')
            
            # Split representations (these don't contain commas)
            representations = representations_str.split(',') if representations_str else []
            
            # For values, we need to match them properly with names
            # The trick is to match count of names with values
            # JSON payloads contain commas, so simple split won't work
            header_values = self._smart_split_values(header_values_str, len(header_names))
            
            # Process each header
            for i, header_name in enumerate(header_names):
                header_name = header_name.strip()
                header_value = header_values[i].strip() if i < len(header_values) else ""
                rep = representations[i].strip() if i < len(representations) else ""
                
                # Identify the header type
                header_type = self.identify_header_type(header_name, header_value)
                
                if header_type is None:
                    continue
                
                # Mark this frame as having JWT
                frames_with_jwt.add(frame_num)
                
                # Extract session ID from payload
                if header_type == 'x-jwt-payload':
                    match = re.search(r'"session_id"\s*:\s*"([a-f0-9-]+)"', header_value)
                    if match:
                        self.unique_sessions.add(match.group(1))
                
                # Track header stats
                self.header_stats[header_type]['sizes'].append(len(header_value))
                value_hash = hashlib.md5(header_value.encode()).hexdigest()[:16]
                self.header_stats[header_type]['unique_values'].add(value_hash)
                
                # Determine if value is indexed or literal
                # "Indexed Header Field" = both name and value from table
                is_value_indexed = rep == 'Indexed Header Field'
                
                # Determine if name is indexed or literal
                # "Indexed Name" = name from table (dynamic or static)
                # "New Name" = name sent literally (first time or not in table)
                is_name_indexed = 'Indexed Name' in rep or rep == 'Indexed Header Field'
                is_name_literal = 'New Name' in rep
                
                if is_value_indexed:
                    self.header_stats[header_type]['indexed'] += 1
                else:
                    self.header_stats[header_type]['literal'] += 1
                
                if is_name_literal:
                    self.header_name_indexing[header_type]['name_literal'] += 1
                elif is_name_indexed:
                    self.header_name_indexing[header_type]['name_indexed'] += 1
                else:
                    # Unknown representation, assume literal
                    self.header_name_indexing[header_type]['name_literal'] += 1
                
                # Byte tracking
                value_size = len(header_value)
                name_size = len(header_type)  # Use actual name size
                
                if value_hash not in self.byte_tracking[header_type]['value_occurrences']:
                    self.byte_tracking[header_type]['value_occurrences'][value_hash] = 0
                self.byte_tracking[header_type]['value_occurrences'][value_hash] += 1
                occurrence_num = self.byte_tracking[header_type]['value_occurrences'][value_hash]
                
                self.byte_tracking[header_type]['potential_bytes'] += name_size + value_size + 2
                
                if is_value_indexed:
                    self.byte_tracking[header_type]['indexed_references'] += 1
                    self.byte_tracking[header_type]['reused_from_table'] += 1
                elif 'Incremental Indexing' in rep:
                    if occurrence_num == 1:
                        self.byte_tracking[header_type]['first_occurrences'] += 1
                    # Name may or may not be indexed
                    if is_name_literal:
                        self.byte_tracking[header_type]['literal_bytes_sent'] += name_size + value_size + 2
                    else:
                        self.byte_tracking[header_type]['literal_bytes_sent'] += value_size + 2
                else:
                    self.byte_tracking[header_type]['literal_bytes_sent'] += name_size + value_size + 2
        
        self.frames_with_jwt = len(frames_with_jwt)
        self.total_frames = len(frames_with_jwt)
    
    def _smart_split_values(self, values_str, expected_count):
        """
        Smart split of header values that handles JSON with commas.
        Uses pattern matching to identify different value types.
        """
        if not values_str:
            return [''] * expected_count
        
        values = []
        remaining = values_str
        
        while remaining and len(values) < expected_count:
            remaining = remaining.strip()
            
            if remaining.startswith('{'):
                # JSON object - find the matching closing brace
                brace_count = 0
                end_idx = 0
                for i, c in enumerate(remaining):
                    if c == '{':
                        brace_count += 1
                    elif c == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                
                if end_idx > 0:
                    values.append(remaining[:end_idx])
                    remaining = remaining[end_idx:]
                    if remaining.startswith(','):
                        remaining = remaining[1:]
                else:
                    # Malformed JSON, take until comma
                    if ',' in remaining:
                        idx = remaining.index(',')
                        values.append(remaining[:idx])
                        remaining = remaining[idx+1:]
                    else:
                        values.append(remaining)
                        remaining = ''
            else:
                # Non-JSON value - take until comma
                if ',' in remaining:
                    idx = remaining.index(',')
                    values.append(remaining[:idx])
                    remaining = remaining[idx+1:]
                else:
                    values.append(remaining)
                    remaining = ''
        
        # Pad with empty strings if needed
        while len(values) < expected_count:
            values.append('')
        
        return values
    
    def print_report(self):
        """Print the analysis report"""
        print("\n" + "=" * 80)
        print("JWT HEADER HPACK INDEXING ANALYSIS REPORT (3-Header Format)")
        print("=" * 80)
        print(f"\nPcap File: {self.pcap_file}")
        print(f"Total Frames with JWT Headers: {self.frames_with_jwt}")
        print(f"Unique Sessions Detected: {len(self.unique_sessions)}")
        
        print("\n" + "=" * 80)
        print("HEADER INDEXING STATISTICS")
        print("=" * 80)
        print()
        print(f"{'Header':<20} {'Total':<10} {'Literal':<10} {'Indexed':<10} {'Index Rate':<12} {'Unique Values':<15}")
        print("-" * 80)
        
        total_uses_all = 0
        total_literal_all = 0
        total_indexed_all = 0
        
        for header in sorted(self.header_stats.keys()):
            stats = self.header_stats[header]
            total = stats['literal'] + stats['indexed']
            total_uses_all += total
            total_literal_all += stats['literal']
            total_indexed_all += stats['indexed']
            
            if total > 0:
                indexing_rate = (stats['indexed'] / total) * 100
            else:
                indexing_rate = 0.0
            
            unique_count = len(stats['unique_values'])
                
            print(f"{header:<20} {total:<10} {stats['literal']:<10} {stats['indexed']:<10} {indexing_rate:>6.1f}%      {unique_count:<15}")
        
        print("-" * 80)
        if total_uses_all > 0:
            overall_rate = (total_indexed_all / total_uses_all) * 100
        else:
            overall_rate = 0.0
        print(f"{'TOTAL':<20} {total_uses_all:<10} {total_literal_all:<10} {total_indexed_all:<10} {overall_rate:>6.1f}%")
        
        # Sanity check
        totals = [self.header_stats[h]['literal'] + self.header_stats[h]['indexed'] 
                  for h in ['x-jwt-header', 'x-jwt-payload', 'x-jwt-sig']]
        if len(set(totals)) > 1:
            print(f"\n⚠️  WARNING: Header totals don't match! {totals}")
            print("    This may indicate parsing issues with the pcap data.")
        
        print("\n" + "=" * 80)
        print("HPACK DYNAMIC TABLE ANALYSIS")
        print("=" * 80)
        
        print("\nHeader Name Indexing (name portion only):")
        print(f"{'Header':<20} {'Name Indexed':<15} {'Name Literal':<15} {'Name Index Rate':<15}")
        print("-" * 70)
        
        for header in sorted(self.header_name_indexing.keys()):
            stats = self.header_name_indexing[header]
            total = stats['name_indexed'] + stats['name_literal']
            if total > 0:
                rate = (stats['name_indexed'] / total) * 100
            else:
                rate = 0.0
            print(f"{header:<20} {stats['name_indexed']:<15} {stats['name_literal']:<15} {rate:>6.1f}%")
        
        print("\nHeader Value Size Statistics:")
        print(f"{'Header':<20} {'Min Size':<12} {'Max Size':<12} {'Avg Size':<12} {'Unique Values':<15}")
        print("-" * 70)
        
        for header in sorted(self.header_stats.keys()):
            stats = self.header_stats[header]
            sizes = stats['sizes']
            if sizes:
                min_size = min(sizes)
                max_size = max(sizes)
                avg_size = sum(sizes) / len(sizes)
            else:
                min_size = max_size = avg_size = 0
            unique_count = len(stats['unique_values'])
            print(f"{header:<20} {min_size:<12} {max_size:<12} {avg_size:<12.1f} {unique_count:<15}")
        
        # Estimate dynamic table usage
        header_stats = self.header_stats.get('x-jwt-header', {})
        payload_stats = self.header_stats.get('x-jwt-payload', {})
        sig_stats = self.header_stats.get('x-jwt-sig', {})
        
        header_sizes = header_stats.get('sizes', [])
        payload_sizes = payload_stats.get('sizes', [])
        sig_sizes = sig_stats.get('sizes', [])
        
        if payload_sizes and sig_sizes:
            avg_header = sum(header_sizes) / len(header_sizes) if header_sizes else 36
            avg_payload = sum(payload_sizes) / len(payload_sizes)
            avg_sig = sum(sig_sizes) / len(sig_sizes)
            
            entry_overhead = 32
            header_entry_size = avg_header + len('x-jwt-header') + entry_overhead
            payload_entry_size = avg_payload + len('x-jwt-payload') + entry_overhead
            sig_entry_size = avg_sig + len('x-jwt-sig') + entry_overhead
            total_entry_size = header_entry_size + payload_entry_size + sig_entry_size
            
            print(f"\nEstimated HPACK Dynamic Table Entry Sizes:")
            print(f"  • x-jwt-header entry: ~{header_entry_size:.0f} bytes (value={avg_header:.0f} + name=12 + overhead=32)")
            print(f"  • x-jwt-payload entry: ~{payload_entry_size:.0f} bytes (value={avg_payload:.0f} + name=13 + overhead=32)")
            print(f"  • x-jwt-sig entry: ~{sig_entry_size:.0f} bytes (value={avg_sig:.0f} + name=9 + overhead=32)")
            print(f"  • Total per request: ~{total_entry_size:.0f} bytes")
            
            default_table_size = 4096
            entries_in_default = default_table_size / total_entry_size
            print(f"\n  With default 4KB table: ~{entries_in_default:.1f} user entries fit")
            
            large_table_size = 512 * 1024
            entries_in_large = large_table_size / total_entry_size
            print(f"  With 512KB table: ~{entries_in_large:.0f} user entries fit")
        
        print("\n" + "=" * 80)
        print("ACTUAL BYTE SAVINGS ANALYSIS")
        print("=" * 80)
        
        print("\n" + "-" * 80)
        print("Breakdown: How bytes were transmitted")
        print("-" * 80)
        print(f"{'Header':<20} {'Potential':<12} {'Literal Sent':<14} {'Indexed Refs':<14} {'Actual Sent':<14} {'Saved':<12}")
        print("-" * 80)
        
        total_potential = 0
        total_actual = 0
        total_saved = 0
        
        for header in sorted(self.byte_tracking.keys()):
            bt = self.byte_tracking[header]
            potential = bt['potential_bytes']
            literal_sent = bt['literal_bytes_sent']
            indexed_refs = bt['indexed_references']
            indexed_bytes = indexed_refs * 2
            actual_sent = literal_sent + indexed_bytes
            saved = potential - actual_sent
            
            total_potential += potential
            total_actual += actual_sent
            total_saved += saved
            
            print(f"{header:<20} {potential:>10,}   {literal_sent:>12,}   {indexed_refs:>6} (~{indexed_bytes:>4})   {actual_sent:>12,}   {saved:>10,}")
        
        print("-" * 80)
        print(f"{'TOTAL':<20} {total_potential:>10,}   {total_actual:>12,}                      {total_actual:>12,}   {total_saved:>10,}")
        
        if total_potential > 0:
            compression_ratio = (1 - total_actual / total_potential) * 100
            print(f"\nOverall compression: {compression_ratio:.1f}% reduction ({total_potential:,} → {total_actual:,} bytes)")
        
        print("\n" + "-" * 80)
        print("Indexing Efficiency Analysis")
        print("-" * 80)
        
        for header in sorted(self.byte_tracking.keys()):
            bt = self.byte_tracking[header]
            stats = self.header_stats[header]
            total_occurrences = stats['literal'] + stats['indexed']
            unique_values = len(bt['value_occurrences'])
            first_occ = bt['first_occurrences']
            reused = bt['reused_from_table']
            
            print(f"\n  {header}:")
            print(f"    • Total header occurrences: {total_occurrences}")
            print(f"    • Unique values seen: {unique_values}")
            print(f"    • First occurrences (must be literal): {first_occ}")
            print(f"    • Reused from dynamic table (indexed): {reused}")
            
            if unique_values > 0:
                reuse_rate = (total_occurrences - unique_values) / total_occurrences * 100 if total_occurrences > 0 else 0
                print(f"    • Value reuse rate: {reuse_rate:.1f}% ({total_occurrences - unique_values} reuses of {total_occurrences} total)")
            
            if reused > 0 and total_occurrences > first_occ:
                potential_reuses = total_occurrences - first_occ
                if potential_reuses > 0:
                    hit_rate = reused / potential_reuses * 100
                    print(f"    • Cache hit rate: {hit_rate:.1f}% ({reused} hits of {potential_reuses} potential reuses)")
            
            evicted_reuses = (total_occurrences - unique_values) - reused
            if evicted_reuses > 0:
                print(f"    • Evicted before reuse: {evicted_reuses} (value was in table but got evicted)")


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_jwt_header_indexing_v2.py <pcap_file>")
        print("\nExample:")
        print("  python analyze_jwt_header_indexing_v2.py jwt-compression-400-on-results-20251205_074543/frontend-cart-traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not Path(pcap_file).exists():
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    analyzer = JWTHeaderAnalyzer(pcap_file)
    analyzer.analyze()
    analyzer.print_report()

if __name__ == "__main__":
    main()
