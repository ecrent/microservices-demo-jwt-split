#!/usr/bin/env python3
"""
Authorization Header HPACK Indexing Analysis (Baseline Test)
Analyzes pcap files to determine how the authorization header is being indexed in HTTP/2 HPACK compression.
This is for the baseline test without JWT header compression (single authorization header).
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
            'authorization': {'literal': 0, 'indexed': 0, 'sessions': set()}
        }
        self.total_frames = 0
        self.frames_with_auth = 0
        self.unique_sessions = set()
        
    def extract_grpc_headers(self):
        """Extract gRPC frames with authorization header and their indexing info"""
        print(f"Analyzing pcap file: {self.pcap_file}")
        print("Extracting gRPC frames with authorization header and indexing details...")
        
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
            
            # Extract session ID from the authorization value
            session_id = None
            auth_value = None
            for i, name in enumerate(header_names):
                if name == 'authorization' and i < len(header_values):
                    auth_value = header_values[i]
                    session_id = self.extract_session_id(auth_value)
                    if session_id:
                        self.unique_sessions.add(session_id)
                    break
            
            # Check if frame has authorization header
            has_auth = False
            
            # Analyze each header in this frame
            for i, header_name in enumerate(header_names):
                if header_name != 'authorization':
                    continue
                
                has_auth = True
                
                # Check representation to determine if literal or indexed
                rep = representations[i] if i < len(representations) else ""
                
                # "Indexed Header Field" = fully indexed (compressed)
                # "Literal Header Field..." = literal transmission (not compressed from index)
                if 'Indexed Header Field' == rep:
                    self.header_stats['authorization']['indexed'] += 1
                elif 'Literal' in rep:
                    self.header_stats['authorization']['literal'] += 1
                else:
                    # Unknown representation, conservatively count as literal
                    self.header_stats['authorization']['literal'] += 1
            
            if has_auth:
                self.frames_with_auth += 1
        
        # Count unique frames
        self.total_frames = len(frames_seen)
    
    def print_report(self):
        """Print the analysis report"""
        print("\n" + "=" * 80)
        print("AUTHORIZATION HEADER HPACK INDEXING ANALYSIS REPORT (BASELINE)")
        print("=" * 80)
        print(f"\nPcap File: {self.pcap_file}")
        print(f"Total Frames Analyzed: {self.total_frames}")
        print(f"Frames with Authorization Header: {self.frames_with_auth}")
        print(f"Unique Sessions Detected: {len(self.unique_sessions)}")
        print("\n" + "=" * 80)
        print("HEADER INDEXING STATISTICS")
        print("=" * 80)
        print()
        print(f"{'Header':<25} {'Total Uses':<12} {'Literal':<10} {'Indexed':<10} {'Indexing Rate':<15}")
        print("-" * 80)
        
        stats = self.header_stats['authorization']
        total = stats['literal'] + stats['indexed']
        
        if total > 0:
            indexing_rate = (stats['indexed'] / total) * 100
        else:
            indexing_rate = 0.0
            
        print(f"{'authorization':<25} {total:<12} {stats['literal']:<10} {stats['indexed']:<10} {indexing_rate:>6.1f}%")
        
        print("\n" + "=" * 80)
        print("COMPARISON WITH JWT COMPRESSION")
        print("=" * 80)
        
        print(f"""
Baseline Test (Single Authorization Header):
- Header count: 1 (authorization header with full JWT token)
- Total uses: {total}
- Literal transmissions: {stats['literal']}
- Indexed transmissions: {stats['indexed']}
- Indexing rate: {indexing_rate:.1f}%

JWT Compression Test (4 Separate Headers):
- Header count: 4 (x-jwt-static, x-jwt-session, x-jwt-dynamic, x-jwt-sig)
- Expected indexing rates:
  * x-jwt-static: ~81% (same for all users)
  * x-jwt-session: ~20% (unique per user, table overflow)
  * x-jwt-dynamic: ~20% (changes on rotation, table overflow)
  * x-jwt-sig: ~20% (changes on rotation, table overflow)

Key Differences:
1. Baseline: Single large header vs Compressed: 4 separate headers
2. Baseline: Entire JWT changes on rotation vs Compressed: Only 2 headers change
3. Baseline: Lower indexing potential vs Compressed: Static header highly indexed
        """)
        
        print("\n" + "=" * 80)
        print("COMPRESSION BENEFITS ANALYSIS")
        print("=" * 80)
        
        # Estimated JWT token size (base64 encoded)
        # Typical JWT: header.payload.signature
        # With 256KB payload: ~350KB base64 encoded
        jwt_size = 350000  # bytes (estimated for 256KB payload JWT)
        
        total_saved = stats['indexed'] * jwt_size
        
        print(f"\nEstimated bandwidth savings from HPACK indexing:")
        print(f"- JWT token size (estimated): ~{jwt_size:,} bytes (~{jwt_size/1024:.0f} KB)")
        print(f"- Indexed transmissions: {stats['indexed']}")
        print(f"- Total saved: ~{total_saved:,} bytes (~{total_saved/1024:.0f} KB, ~{total_saved/(1024*1024):.2f} MB)")
        
        if self.frames_with_auth > 0:
            avg_per_frame = total_saved / self.frames_with_auth
            print(f"- Average savings per frame: ~{avg_per_frame:,.0f} bytes (~{avg_per_frame/1024:.1f} KB)")
        
        if len(self.unique_sessions) > 0:
            avg_per_session = total_saved / len(self.unique_sessions)
            print(f"- Average savings per session: ~{avg_per_session:,.0f} bytes (~{avg_per_session/1024:.1f} KB)")
        
        print("\n" + "=" * 80)
        print("ANALYSIS NOTES")
        print("=" * 80)
        print("""
1. LITERAL: Header transmitted with full name and value (first occurrence per session)
2. INDEXED: Header referenced by index number from HPACK dynamic table
3. Indexing Rate: Percentage of header uses that were indexed (higher is better)
4. The authorization header contains the complete JWT token (header.payload.signature)
5. Every JWT rotation requires sending the entire new token as literal
6. With 400 concurrent users and large JWTs, dynamic table eviction is common

Baseline Test Characteristics:
- Uses standard "authorization: Bearer <jwt>" header format
- Entire JWT token sent in single header
- JWT rotation forces complete re-transmission of entire token
- HPACK can index the entire token value if it fits in dynamic table
- With 256KB JWT payload, token is ~350KB - may exceed HPACK table capacity
        """)

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
