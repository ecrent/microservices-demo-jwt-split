#!/usr/bin/env python3
"""
JWT Header HPACK Indexing Analysis (2-Header Format)
Analyzes pcap files to determine how JWT headers are being indexed in HTTP/2 HPACK compression.

New 2-Header Format:
- x-jwt-payload: Raw JSON payload (not base64 encoded)
- x-jwt-sig: Base64url signature only
- JWT header is hardcoded constant (not transmitted)
"""

import subprocess
import re
import json
from collections import defaultdict
from pathlib import Path

class JWTHeaderAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        # New 2-header format
        self.header_stats = {
            'x-jwt-payload': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()},
            'x-jwt-sig': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()}
        }
        self.total_frames = 0
        self.frames_with_jwt = 0
        self.unique_sessions = set()
        self.header_name_indexing = {'x-jwt-payload': {'name_indexed': 0, 'name_literal': 0},
                                      'x-jwt-sig': {'name_indexed': 0, 'name_literal': 0}}
        # Track actual byte transmission for savings calculation
        self.byte_tracking = {
            'x-jwt-payload': {
                'literal_bytes_sent': 0,       # Actual bytes sent as literal
                'indexed_references': 0,        # Number of indexed references (1-2 bytes each)
                'first_occurrences': 0,         # First time a value was seen (must be literal)
                'reused_from_table': 0,         # Successfully reused from dynamic table
                'potential_bytes': 0,           # What would have been sent without any HPACK
                'value_occurrences': {},        # Track each value's occurrence count
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
        
    def extract_grpc_headers(self):
        """Extract HTTP/2 frames with JWT headers and their indexing info"""
        print(f"Analyzing pcap file: {self.pcap_file}")
        print("Extracting HTTP/2 frames with JWT headers and indexing details...")
        print("Looking for headers: x-jwt-payload, x-jwt-sig")
        
        # Extract header names and their representation (indexed vs literal)
        # Using http2 filter instead of grpc for better header capture
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
            '-E', 'separator=|'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            print(f"Error running tshark: {e}")
            return []
    
    def parse_frame(self, frame_data):
        """Parse a single frame's data"""
        if not frame_data.strip():
            return None
            
        parts = frame_data.split('|')
        if len(parts) < 4:
            return None
            
        frame_num = parts[0]
        stream_ids = parts[1] if len(parts) > 1 else ""
        header_names = parts[2] if len(parts) > 2 else ""
        header_values = parts[3] if len(parts) > 3 else ""
        representations = parts[4] if len(parts) > 4 else ""
        
        # Check if this frame contains our JWT headers (x-jwt-payload or x-jwt-sig)
        if 'x-jwt-payload' not in header_names and 'x-jwt-sig' not in header_names:
            return None
            
        return {
            'frame_num': frame_num,
            'stream_ids': stream_ids,
            'header_names': header_names,
            'header_values': header_values,
            'representations': representations
        }
    
    def extract_session_id(self, header_values):
        """Extract session ID from x-jwt-payload (raw JSON)"""
        # x-jwt-payload contains raw JSON like: {"session_id":"xxx",...}
        match = re.search(r'"session_id"\s*:\s*"([a-f0-9-]+)"', header_values)
        if match:
            return match.group(1)
        return None
    
    def extract_payload_from_values(self, header_names, header_values):
        """Extract the x-jwt-payload value from header lists"""
        names = [h.strip() for h in header_names.split(',')]
        values = [v.strip() for v in header_values.split(',')]
        
        for i, name in enumerate(names):
            if name == 'x-jwt-payload' and i < len(values):
                return values[i]
        return None
    
    def analyze(self):
        """Run the full analysis"""
        frames = self.extract_grpc_headers()
        
        print(f"Processing {len(frames)} lines of output...")
        
        frames_seen = set()
        
        for frame_data in frames:
            parsed = self.parse_frame(frame_data)
            if not parsed:
                continue
            
            frame_num = parsed['frame_num']
            
            # Track unique frames
            frames_seen.add(frame_num)
            
            # Split the comma-separated fields
            header_names = [h.strip() for h in parsed['header_names'].split(',') if h.strip()]
            header_values = [v.strip() for v in parsed['header_values'].split(',') if v.strip()]
            representations = [r.strip() for r in parsed['representations'].split(',') if r.strip()]
            
            # Extract session ID from the payload
            session_id = self.extract_session_id(parsed['header_values'])
            if session_id:
                self.unique_sessions.add(session_id)
            
            # Check if frame has JWT headers
            has_jwt = False
            
            # Analyze each header in this frame
            for i, header_name in enumerate(header_names):
                # Only process our JWT headers
                if header_name not in ['x-jwt-payload', 'x-jwt-sig']:
                    continue
                
                has_jwt = True
                
                if header_name not in self.header_stats:
                    continue
                
                # Track header value size
                if i < len(header_values):
                    value = header_values[i]
                    self.header_stats[header_name]['sizes'].append(len(value))
                    # Track unique values (hash for memory efficiency)
                    import hashlib
                    value_hash = hashlib.md5(value.encode()).hexdigest()[:16]
                    self.header_stats[header_name]['unique_values'].add(value_hash)
                
                # Check representation to determine if literal or indexed
                rep = representations[i] if i < len(representations) else ""
                
                # HPACK representation types:
                # "Indexed Header Field" = fully indexed (name + value from table)
                # "Literal Header Field with Incremental Indexing" = name indexed, value literal, will be added to table
                # "Literal Header Field without Indexing" = not added to table
                # "Literal Header Field never Indexed" = sensitive, never indexed
                
                # Get value for byte tracking
                value = header_values[i] if i < len(header_values) else ""
                value_size = len(value)
                name_size = len(header_name)
                import hashlib
                value_hash = hashlib.md5(value.encode()).hexdigest()[:16]
                
                # Track value occurrences
                if value_hash not in self.byte_tracking[header_name]['value_occurrences']:
                    self.byte_tracking[header_name]['value_occurrences'][value_hash] = 0
                self.byte_tracking[header_name]['value_occurrences'][value_hash] += 1
                occurrence_num = self.byte_tracking[header_name]['value_occurrences'][value_hash]
                
                # Potential bytes = what would be sent without HPACK (name + value + small overhead)
                self.byte_tracking[header_name]['potential_bytes'] += name_size + value_size + 2
                
                if rep == 'Indexed Header Field':
                    self.header_stats[header_name]['indexed'] += 1
                    self.header_name_indexing[header_name]['name_indexed'] += 1
                    # Indexed = only 1-2 bytes sent for the index reference
                    self.byte_tracking[header_name]['indexed_references'] += 1
                    self.byte_tracking[header_name]['reused_from_table'] += 1
                elif 'Incremental Indexing' in rep:
                    # Name might be indexed, value is literal but will be added to table
                    self.header_stats[header_name]['literal'] += 1
                    self.header_name_indexing[header_name]['name_indexed'] += 1
                    # Literal with indexing = full value sent, but will be cached
                    if occurrence_num == 1:
                        self.byte_tracking[header_name]['first_occurrences'] += 1
                    self.byte_tracking[header_name]['literal_bytes_sent'] += value_size + 2  # +2 for length prefix
                elif 'Literal' in rep:
                    self.header_stats[header_name]['literal'] += 1
                    self.header_name_indexing[header_name]['name_literal'] += 1
                    self.byte_tracking[header_name]['literal_bytes_sent'] += name_size + value_size + 2
                else:
                    # Unknown representation
                    self.header_stats[header_name]['literal'] += 1
                    self.header_name_indexing[header_name]['name_literal'] += 1
                    self.byte_tracking[header_name]['literal_bytes_sent'] += name_size + value_size + 2
            
            if has_jwt:
                self.frames_with_jwt += 1
        
        # Count unique frames
        self.total_frames = len(frames_seen)
    
    def print_report(self):
        """Print the analysis report"""
        print("\n" + "=" * 80)
        print("JWT HEADER HPACK INDEXING ANALYSIS REPORT (2-Header Format)")
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
        payload_stats = self.header_stats.get('x-jwt-payload', {})
        sig_stats = self.header_stats.get('x-jwt-sig', {})
        
        payload_sizes = payload_stats.get('sizes', [])
        sig_sizes = sig_stats.get('sizes', [])
        
        if payload_sizes and sig_sizes:
            avg_payload = sum(payload_sizes) / len(payload_sizes)
            avg_sig = sum(sig_sizes) / len(sig_sizes)
            
            # HPACK entry overhead: 32 bytes per entry
            entry_overhead = 32
            payload_entry_size = avg_payload + len('x-jwt-payload') + entry_overhead
            sig_entry_size = avg_sig + len('x-jwt-sig') + entry_overhead
            total_entry_size = payload_entry_size + sig_entry_size
            
            print(f"\nEstimated HPACK Dynamic Table Entry Sizes:")
            print(f"  • x-jwt-payload entry: ~{payload_entry_size:.0f} bytes (value={avg_payload:.0f} + name=13 + overhead=32)")
            print(f"  • x-jwt-sig entry: ~{sig_entry_size:.0f} bytes (value={avg_sig:.0f} + name=9 + overhead=32)")
            print(f"  • Total per request: ~{total_entry_size:.0f} bytes")
            
            # With default 4KB table
            default_table_size = 4096
            entries_in_default = default_table_size / total_entry_size
            print(f"\n  With default 4KB table: ~{entries_in_default:.1f} user entries fit")
            
            # With 512KB table
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
            # Indexed references are ~2 bytes each
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
                # Calculate how many potential reuses actually hit the cache
                potential_reuses = total_occurrences - first_occ
                if potential_reuses > 0:
                    hit_rate = reused / potential_reuses * 100
                    print(f"    • Cache hit rate: {hit_rate:.1f}% ({reused} hits of {potential_reuses} potential reuses)")
            
            # Show eviction analysis
            evicted_reuses = (total_occurrences - unique_values) - reused
            if evicted_reuses > 0:
                print(f"    • Evicted before reuse: {evicted_reuses} (value was in table but got evicted)")
        


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_jwt_header_indexing.py <pcap_file>")
        print("\nExample:")
        print("  python analyze_jwt_header_indexing.py jwt-compression-results-on-400-256kb-wsl-longduration-20251022_073455/frontend-cart-traffic.pcap")
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
