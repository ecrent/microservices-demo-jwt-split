#!/usr/bin/env python3
"""
Authorization Header HPACK Indexing Analysis (Baseline - Compression OFF)
Analyzes pcap files to determine how the authorization header is being indexed in HTTP/2 HPACK compression.
This is for the baseline test without JWT header compression (single authorization header with full JWT).

Comparison with 2-Header Format:
- Baseline: authorization: Bearer <header.payload.signature>
- Compressed: x-jwt-payload (raw JSON) + x-jwt-sig (signature only)
"""

import subprocess
import re
import json
from collections import defaultdict
from pathlib import Path

class AuthHeaderAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.header_stats = {
            'authorization': {'literal': 0, 'indexed': 0, 'sizes': [], 'unique_values': set()}
        }
        self.total_frames = 0
        self.frames_with_auth = 0
        self.unique_sessions = set()
        self.header_name_indexing = {'authorization': {'name_indexed': 0, 'name_literal': 0}}
        # Track actual byte transmission for savings calculation
        self.byte_tracking = {
            'authorization': {
                'literal_bytes_sent': 0,       # Actual bytes sent as literal
                'indexed_references': 0,        # Number of indexed references (1-2 bytes each)
                'first_occurrences': 0,         # First time a value was seen (must be literal)
                'reused_from_table': 0,         # Successfully reused from dynamic table
                'potential_bytes': 0,           # What would have been sent without any HPACK
                'value_occurrences': {},        # Track each value's occurrence count
            }
        }
        
    def extract_grpc_headers(self):
        """Extract HTTP/2 frames with authorization header and their indexing info"""
        print(f"Analyzing pcap file: {self.pcap_file}")
        print("Extracting HTTP/2 frames with authorization header and indexing details...")
        print("Looking for header: authorization (Bearer JWT)")
        
        # Extract header names and their representation (indexed vs literal)
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
        
        # Check if this frame contains authorization header
        if 'authorization' not in header_names:
            return None
            
        return {
            'frame_num': frame_num,
            'stream_ids': stream_ids,
            'header_names': header_names,
            'header_values': header_values,
            'representations': representations
        }
    
    def extract_session_id(self, auth_value):
        """Extract session ID from JWT in authorization header"""
        # Authorization header format: "Bearer <jwt_token>"
        # JWT is in format: header.payload.signature
        # We need to decode the payload to get session_id
        if not auth_value or 'Bearer' not in auth_value:
            return None
        
        # For now, just use a hash of the full token as identifier
        # In production, you'd decode the JWT payload
        import hashlib
        token_hash = hashlib.md5(auth_value.encode()).hexdigest()[:8]
        return token_hash
    
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
            
            # Extract session ID from the authorization value
            session_id = None
            auth_value = None
            for i, name in enumerate(header_names):
                if name == 'authorization' and i < len(header_values):
                    auth_value = header_values[i]
                    session_id = self.extract_session_id(auth_value)
                    if session_id:
                        self.unique_sessions.add(session_id)
                    # Track value size and uniqueness
                    self.header_stats['authorization']['sizes'].append(len(auth_value))
                    import hashlib
                    value_hash = hashlib.md5(auth_value.encode()).hexdigest()[:16]
                    self.header_stats['authorization']['unique_values'].add(value_hash)
                    break
            
            # Check if frame has authorization header
            has_auth = False
            
            # Analyze each header in this frame
            for i, header_name in enumerate(header_names):
                if header_name != 'authorization':
                    continue
                
                has_auth = True
                
                # Get value for byte tracking
                value = auth_value if auth_value else ""
                value_size = len(value)
                name_size = len('authorization')
                import hashlib
                value_hash = hashlib.md5(value.encode()).hexdigest()[:16]
                
                # Track value occurrences
                if value_hash not in self.byte_tracking['authorization']['value_occurrences']:
                    self.byte_tracking['authorization']['value_occurrences'][value_hash] = 0
                self.byte_tracking['authorization']['value_occurrences'][value_hash] += 1
                occurrence_num = self.byte_tracking['authorization']['value_occurrences'][value_hash]
                
                # Potential bytes = what would be sent without HPACK (name + value + small overhead)
                self.byte_tracking['authorization']['potential_bytes'] += name_size + value_size + 2
                
                # Check representation to determine if literal or indexed
                rep = representations[i] if i < len(representations) else ""
                
                # HPACK representation types
                if rep == 'Indexed Header Field':
                    self.header_stats['authorization']['indexed'] += 1
                    self.header_name_indexing['authorization']['name_indexed'] += 1
                    # Indexed = only 1-2 bytes sent for the index reference
                    self.byte_tracking['authorization']['indexed_references'] += 1
                    self.byte_tracking['authorization']['reused_from_table'] += 1
                elif 'Incremental Indexing' in rep:
                    self.header_stats['authorization']['literal'] += 1
                    self.header_name_indexing['authorization']['name_indexed'] += 1
                    # Literal with indexing = full value sent, but will be cached
                    if occurrence_num == 1:
                        self.byte_tracking['authorization']['first_occurrences'] += 1
                    self.byte_tracking['authorization']['literal_bytes_sent'] += value_size + 2  # +2 for length prefix
                elif 'Literal' in rep:
                    self.header_stats['authorization']['literal'] += 1
                    self.header_name_indexing['authorization']['name_literal'] += 1
                    self.byte_tracking['authorization']['literal_bytes_sent'] += name_size + value_size + 2
                else:
                    self.header_stats['authorization']['literal'] += 1
                    self.header_name_indexing['authorization']['name_literal'] += 1
                    self.byte_tracking['authorization']['literal_bytes_sent'] += name_size + value_size + 2
            
            if has_auth:
                self.frames_with_auth += 1
        
        # Count unique frames
        self.total_frames = len(frames_seen)
    
    def print_report(self):
        """Print the analysis report"""
        print("\n" + "=" * 80)
        print("AUTHORIZATION HEADER HPACK INDEXING ANALYSIS (Baseline - Compression OFF)")
        print("=" * 80)
        print(f"\nPcap File: {self.pcap_file}")
        print(f"Total Frames Analyzed: {self.total_frames}")
        print(f"Frames with Authorization Header: {self.frames_with_auth}")
        print(f"Unique Sessions Detected: {len(self.unique_sessions)}")
        
        print("\n" + "=" * 80)
        print("HEADER INDEXING STATISTICS")
        print("=" * 80)
        print()
        
        stats = self.header_stats['authorization']
        total = stats['literal'] + stats['indexed']
        unique_count = len(stats['unique_values'])
        
        if total > 0:
            indexing_rate = (stats['indexed'] / total) * 100
        else:
            indexing_rate = 0.0
        
        print(f"{'Header':<20} {'Total':<10} {'Literal':<10} {'Indexed':<10} {'Index Rate':<12} {'Unique Values':<15}")
        print("-" * 80)
        print(f"{'authorization':<20} {total:<10} {stats['literal']:<10} {stats['indexed']:<10} {indexing_rate:>6.1f}%      {unique_count:<15}")
        
        print("\n" + "=" * 80)
        print("HPACK DYNAMIC TABLE ANALYSIS")
        print("=" * 80)
        
        # Header name indexing
        name_stats = self.header_name_indexing['authorization']
        name_total = name_stats['name_indexed'] + name_stats['name_literal']
        if name_total > 0:
            name_rate = (name_stats['name_indexed'] / name_total) * 100
        else:
            name_rate = 0.0
        
        print("\nHeader Name Indexing:")
        print(f"  • 'authorization' name indexed: {name_stats['name_indexed']} ({name_rate:.1f}%)")
        print(f"  • 'authorization' name literal: {name_stats['name_literal']}")
        
        # Value size statistics
        sizes = stats['sizes']
        if sizes:
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
            print(f"\nHeader Value Size Statistics:")
            print(f"  • Min size: {min_size} bytes")
            print(f"  • Max size: {max_size} bytes")
            print(f"  • Avg size: {avg_size:.1f} bytes")
            print(f"  • Unique values: {unique_count}")
            
            # HPACK entry size calculation
            entry_overhead = 32
            entry_size = avg_size + len('authorization') + entry_overhead
            print(f"\nEstimated HPACK Dynamic Table Entry Size:")
            print(f"  • Entry size: ~{entry_size:.0f} bytes (value={avg_size:.0f} + name=13 + overhead=32)")
            
            # Table capacity analysis
            default_table = 4096
            large_table = 512 * 1024
            entries_default = default_table / entry_size
            entries_large = large_table / entry_size
            print(f"\n  With default 4KB table: ~{entries_default:.1f} entries fit")
            print(f"  With 512KB table: ~{entries_large:.0f} entries fit")
        
        print("\n" + "=" * 80)
        print("ACTUAL BYTE SAVINGS ANALYSIS")
        print("=" * 80)
        
        bt = self.byte_tracking['authorization']
        potential = bt['potential_bytes']
        literal_sent = bt['literal_bytes_sent']
        indexed_refs = bt['indexed_references']
        indexed_bytes = indexed_refs * 2  # ~2 bytes per index reference
        actual_sent = literal_sent + indexed_bytes
        saved = potential - actual_sent
        
        print("\n" + "-" * 80)
        print("Breakdown: How bytes were transmitted")
        print("-" * 80)
        print(f"{'Header':<20} {'Potential':<12} {'Literal Sent':<14} {'Indexed Refs':<14} {'Actual Sent':<14} {'Saved':<12}")
        print("-" * 80)
        print(f"{'authorization':<20} {potential:>10,}   {literal_sent:>12,}   {indexed_refs:>6} (~{indexed_bytes:>4})   {actual_sent:>12,}   {saved:>10,}")
        
        if potential > 0:
            compression_ratio = (1 - actual_sent / potential) * 100
            print(f"\nOverall compression: {compression_ratio:.1f}% reduction ({potential:,} → {actual_sent:,} bytes)")
        
        print("\n" + "-" * 80)
        print("Indexing Efficiency Analysis")
        print("-" * 80)
        
        total_occurrences = self.header_stats['authorization']['literal'] + self.header_stats['authorization']['indexed']
        unique_values = len(bt['value_occurrences'])
        first_occ = bt['first_occurrences']
        reused = bt['reused_from_table']
        
        print(f"\n  authorization:")
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
        
        # Show eviction analysis
        evicted_reuses = (total_occurrences - unique_values) - reused
        if evicted_reuses > 0:
            print(f"    • Evicted before reuse: {evicted_reuses} (value was in table but got evicted)")
        
        print("\n" + "="*80)

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_auth_header_indexing.py <pcap_file>")
        print("\nExample:")
        print("  python analyze_auth_header_indexing.py jwt-compression-results-off-400-256kb-wsl-longduration-20251022_074346/frontend-cart-traffic.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not Path(pcap_file).exists():
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    analyzer = AuthHeaderAnalyzer(pcap_file)
    analyzer.analyze()
    analyzer.print_report()

if __name__ == "__main__":
    main()
