#!/usr/bin/env python3
"""
JWT Header HPACK Indexing Analysis
Analyzes pcap files to determine how JWT headers are being indexed in HTTP/2 HPACK compression.
"""

import subprocess
import re
import json
from collections import defaultdict
from pathlib import Path

class JWTHeaderAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.header_stats = {
            'x-jwt-static': {'literal': 0, 'indexed': 0, 'sessions': set()},
            'x-jwt-session': {'literal': 0, 'indexed': 0, 'sessions': set()},
            'x-jwt-dynamic': {'literal': 0, 'indexed': 0, 'sessions': set()},
            'x-jwt-sig': {'literal': 0, 'indexed': 0, 'sessions': set()}
        }
        self.total_frames = 0
        self.frames_with_jwt = 0
        self.unique_sessions = set()
        
    def extract_grpc_headers(self):
        """Extract gRPC frames with JWT headers and their indexing info"""
        print(f"Analyzing pcap file: {self.pcap_file}")
        print("Extracting gRPC frames with JWT headers and indexing details...")
        
        # Extract header names and their representation (indexed vs literal)
        cmd = [
            'tshark', '-r', self.pcap_file,
            '-Y', 'grpc',
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
        
        # Check if this frame contains JWT headers
        if 'x-jwt' not in header_names:
            return None
            
        return {
            'frame_num': frame_num,
            'stream_ids': stream_ids,
            'header_names': header_names,
            'header_values': header_values,
            'representations': representations
        }
    
    def extract_session_id(self, header_values):
        """Extract session ID from header values"""
        # Look for session_id in the header values
        match = re.search(r'"session_id":"([a-f0-9-]+)"', header_values)
        if match:
            return match.group(1)
        return None
    
    def analyze_frame(self, frame_data):
        """Analyze a single frame for JWT header usage"""
        parsed = self.parse_frame(frame_data)
        if not parsed:
            return
            
        self.total_frames += 1
        
        # Extract session ID
        session_id = self.extract_session_id(parsed['header_values'])
        if session_id:
            self.unique_sessions.add(session_id)
        
        # Count JWT headers in this frame
        header_names = [h.strip() for h in parsed['header_names'].split(',')]
        jwt_headers = [h for h in header_names if h.startswith('x-jwt')]
        
        if not jwt_headers:
            return
            
        self.frames_with_jwt += 1
        
        # Track each JWT header appearance
        for header in jwt_headers:
            if header in self.header_stats:
                if session_id:
                    self.header_stats[header]['sessions'].add(session_id)
                
                # First appearance is literal, subsequent are indexed
                # We use a simple heuristic: if we've seen this session before, it's indexed
                if session_id and session_id not in self.header_stats[header]['sessions']:
                    self.header_stats[header]['literal'] += 1
                    self.header_stats[header]['sessions'].add(session_id)
                else:
                    self.header_stats[header]['indexed'] += 1
    
    def analyze(self):
        """Run the full analysis"""
        frames = self.extract_grpc_headers()
        
        print(f"Processing {len(frames)} frames...")
        
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
            
            # Extract session ID from the values
            session_id = None
            for value in header_values:
                extracted = self.extract_session_id(value)
                if extracted:
                    session_id = extracted
                    self.unique_sessions.add(session_id)
                    break
            
            # Check if frame has JWT headers
            has_jwt = False
            
            # Analyze each header in this frame
            for i, header_name in enumerate(header_names):
                if not header_name.startswith('x-jwt'):
                    continue
                
                has_jwt = True
                
                if header_name not in self.header_stats:
                    continue
                
                # Check representation to determine if literal or indexed
                rep = representations[i] if i < len(representations) else ""
                
                # "Indexed Header Field" = fully indexed (compressed)
                # "Literal Header Field..." = literal transmission (not compressed from index)
                if 'Indexed Header Field' == rep:
                    self.header_stats[header_name]['indexed'] += 1
                elif 'Literal' in rep:
                    self.header_stats[header_name]['literal'] += 1
                else:
                    # Unknown representation, conservatively count as literal
                    self.header_stats[header_name]['literal'] += 1
            
            if has_jwt:
                self.frames_with_jwt += 1
        
        # Count unique frames
        self.total_frames = len(frames_seen)
    
    def print_report(self):
        """Print the analysis report"""
        print("\n" + "=" * 80)
        print("JWT HEADER HPACK INDEXING ANALYSIS REPORT")
        print("=" * 80)
        print(f"\nPcap File: {self.pcap_file}")
        print(f"Total Frames Analyzed: {self.total_frames}")
        print(f"Frames with JWT Headers: {self.frames_with_jwt}")
        print(f"Unique Sessions Detected: {len(self.unique_sessions)}")
        print("\n" + "=" * 80)
        print("HEADER INDEXING STATISTICS")
        print("=" * 80)
        print()
        print(f"{'Header':<25} {'Total Uses':<12} {'Literal':<10} {'Indexed':<10} {'Indexing Rate':<15}")
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
                
            print(f"{header:<25} {total:<12} {stats['literal']:<10} {stats['indexed']:<10} {indexing_rate:>6.1f}%")
        
        print("-" * 80)
        if total_uses_all > 0:
            overall_rate = (total_indexed_all / total_uses_all) * 100
        else:
            overall_rate = 0.0
        print(f"{'TOTAL':<25} {total_uses_all:<12} {total_literal_all:<10} {total_indexed_all:<10} {overall_rate:>6.1f}%")
        
        print("\n" + "=" * 80)
        print("COMPRESSION BENEFITS")
        print("=" * 80)
        
        # Estimated sizes
        sizes = {
            'x-jwt-static': 150,
            'x-jwt-session': 200,
            'x-jwt-dynamic': 220,
            'x-jwt-sig': 350
        }
        
        total_saved = 0
        print("\nEstimated bandwidth savings from HPACK indexing:")
        print(f"{'Header':<25} {'Indexed Uses':<15} {'Size/Header':<15} {'Total Saved':<15}")
        print("-" * 80)
        
        for header in sorted(self.header_stats.keys()):
            stats = self.header_stats[header]
            size = sizes.get(header, 200)
            saved = stats['indexed'] * size
            total_saved += saved
            print(f"{header:<25} {stats['indexed']:<15} {size:<15} ~{saved:,} bytes")
        
        print("-" * 80)
        print(f"{'TOTAL SAVED':<25} {'':<15} {'':<15} ~{total_saved:,} bytes")
        print(f"\nTotal bandwidth saved: ~{total_saved / 1024:.2f} KB (~{total_saved / (1024*1024):.2f} MB)")
        
        if self.frames_with_jwt > 0:
            avg_per_frame = total_saved / self.frames_with_jwt
            print(f"Average savings per frame: ~{avg_per_frame:.0f} bytes")
        
        if len(self.unique_sessions) > 0:
            avg_per_session = total_saved / len(self.unique_sessions)
            print(f"Average savings per session: ~{avg_per_session:,.0f} bytes (~{avg_per_session/1024:.2f} KB)")
        
        print("\n" + "=" * 80)
        print("ANALYSIS NOTES")
        print("=" * 80)
        print("""
1. LITERAL: Header transmitted with full name and value (first occurrence per session)
2. INDEXED: Header referenced by index number from HPACK dynamic table
3. Indexing Rate: Percentage of header uses that were indexed (higher is better)
4. The first request for each session transmits headers as literals
5. Subsequent requests reference the indexed values, saving bandwidth
6. High indexing rates (>90%) indicate excellent HPACK compression efficiency
        """)

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
