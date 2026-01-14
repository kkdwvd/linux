#!/usr/bin/env python3
"""
BPF Subsystem Commit Statistics Analyzer

This script analyzes commit activity across the BPF subsystem by:
1. Parsing the MAINTAINERS file to identify BPF-controlled files
2. Classifying files by their MAINTAINERS section (BPF CORE, XDP, etc.)
3. For each kernel version range, counting commits per file/section
4. Presenting statistics in a readable format
"""

import subprocess
import re
import fnmatch
import argparse
import json
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MaintainerSection:
    """Represents a section in the MAINTAINERS file"""
    name: str
    file_patterns: list = field(default_factory=list)
    exclude_patterns: list = field(default_factory=list)
    maintainers: list = field(default_factory=list)
    status: str = ""


def parse_maintainers(maintainers_path: str) -> list[MaintainerSection]:
    """Parse the MAINTAINERS file and extract BPF/XDP related sections"""
    sections = []
    current_section: Optional[MaintainerSection] = None

    # Patterns to identify BPF-related section headers
    bpf_section_pattern = re.compile(r'^(BPF|XDP)\b.*$')

    with open(maintainers_path, 'r') as f:
        for line in f:
            line = line.rstrip('\n')

            # Check if this is a new section header (non-indented, non-empty line
            # that doesn't start with a field identifier)
            if line and not line[0].isspace() and not line.startswith(('M:', 'R:', 'L:', 'S:', 'W:', 'Q:', 'T:', 'P:', 'F:', 'X:', 'N:', 'K:', 'B:', 'C:')):
                # Save previous section if it was BPF-related
                if current_section:
                    sections.append(current_section)
                    current_section = None

                # Check if new section is BPF-related
                if bpf_section_pattern.match(line):
                    current_section = MaintainerSection(name=line)

            elif current_section:
                # Parse field lines
                if line.startswith('M:\t') or line.startswith('M:	'):
                    current_section.maintainers.append(line[3:].strip())
                elif line.startswith('F:\t') or line.startswith('F:	'):
                    current_section.file_patterns.append(line[3:].strip())
                elif line.startswith('X:\t') or line.startswith('X:	'):
                    current_section.exclude_patterns.append(line[3:].strip())
                elif line.startswith('S:\t') or line.startswith('S:	'):
                    current_section.status = line[3:].strip()

        # Don't forget the last section
        if current_section:
            sections.append(current_section)

    return sections


def get_version_tags(start_version: str, end_version: str) -> list[str]:
    """Get list of kernel version tags between start and end"""
    # Parse version numbers
    start_parts = [int(x) for x in start_version.split('.')]
    end_parts = [int(x) for x in end_version.split('.')]

    tags = []
    major = start_parts[0]
    minor = start_parts[1]

    while (major, minor) <= (end_parts[0], end_parts[1]):
        tag = f"v{major}.{minor}"
        # Verify tag exists
        result = subprocess.run(
            ['git', 'rev-parse', '--verify', tag],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            tags.append(tag)
        minor += 1

    return tags


def get_files_touched_in_range(start_tag: str, end_tag: str) -> dict[str, int]:
    """Get all files touched between two git tags with commit counts"""
    result = subprocess.run(
        ['git', 'log', '--name-only', '--pretty=format:', f'{start_tag}..{end_tag}'],
        capture_output=True,
        text=True
    )

    file_counts = defaultdict(int)
    for line in result.stdout.strip().split('\n'):
        if line:
            file_counts[line] += 1

    return file_counts


def get_commits_for_file(start_tag: str, end_tag: str, file_path: str) -> list[str]:
    """Get list of commit hashes touching a specific file"""
    result = subprocess.run(
        ['git', 'log', '--pretty=format:%h', f'{start_tag}..{end_tag}', '--', file_path],
        capture_output=True,
        text=True
    )

    return [h for h in result.stdout.strip().split('\n') if h]


def match_file_to_pattern(file_path: str, pattern: str) -> bool:
    """Check if a file path matches a MAINTAINERS pattern"""
    # MAINTAINERS uses glob-like patterns
    # Convert to proper glob pattern
    if pattern.endswith('/'):
        # Directory pattern - match anything under it
        pattern = pattern + '*'

    # Handle ** for recursive matching
    if '**' in pattern:
        # fnmatch doesn't support **, so we need special handling
        parts = pattern.split('**')
        if len(parts) == 2:
            prefix, suffix = parts
            if file_path.startswith(prefix.rstrip('/')):
                remaining = file_path[len(prefix.rstrip('/')):]
                if suffix:
                    return fnmatch.fnmatch(remaining, '*' + suffix) or fnmatch.fnmatch(remaining.split('/')[-1], suffix.lstrip('/'))
                return True
        return fnmatch.fnmatch(file_path, pattern.replace('**', '*'))

    return fnmatch.fnmatch(file_path, pattern)


def classify_file(file_path: str, sections: list[MaintainerSection]) -> list[str]:
    """Classify a file into MAINTAINERS sections"""
    matched_sections = []

    for section in sections:
        # Check if excluded first
        excluded = False
        for excl_pattern in section.exclude_patterns:
            if match_file_to_pattern(file_path, excl_pattern):
                excluded = True
                break

        if excluded:
            continue

        # Check if matches any file pattern
        for pattern in section.file_patterns:
            if match_file_to_pattern(file_path, pattern):
                matched_sections.append(section.name)
                break

    return matched_sections


def is_selftest_file(file_path: str) -> bool:
    """Check if a file is a BPF selftest file"""
    return 'tools/testing/selftests/bpf' in file_path


def is_documentation_file(file_path: str) -> bool:
    """Check if file is documentation"""
    return file_path.startswith('Documentation/')


def is_sample_file(file_path: str) -> bool:
    """Check if file is a sample"""
    return file_path.startswith('samples/bpf/')


def is_tool_file(file_path: str) -> bool:
    """Check if file is from tools/"""
    return file_path.startswith('tools/') and not is_selftest_file(file_path)


# =============================================================================
# Symbol Dependency Analysis Types
# =============================================================================

@dataclass
class ExportedSymbol:
    """Represents an exported kernel symbol"""
    name: str
    export_type: str  # "GPL", "non-GPL"
    defined_in: str   # file path
    line: int


@dataclass
class SymbolUsage:
    """Tracks usage of a symbol across files"""
    symbol: str
    export_type: str  # "GPL", "non-GPL", "not-exported"
    defined_in: str   # where the export is defined (if exported)
    used_by: dict = field(default_factory=lambda: defaultdict(list))  # file -> list of line numbers


@dataclass
class CategorySymbolDeps:
    """Symbol dependencies for a location category"""
    category: str
    files_analyzed: int = 0
    gpl_symbols: dict = field(default_factory=dict)  # symbol -> SymbolUsage
    non_gpl_symbols: dict = field(default_factory=dict)  # symbol -> SymbolUsage
    not_exported_symbols: dict = field(default_factory=dict)  # symbol -> SymbolUsage


# =============================================================================
# Commit Statistics Types
# =============================================================================

@dataclass
class VersionStats:
    """Statistics for a kernel version range"""
    start_tag: str
    end_tag: str
    section_stats: dict = field(default_factory=lambda: defaultdict(lambda: {'files': defaultdict(int), 'total_commits': 0}))
    selftest_commits: int = 0
    selftest_files: set = field(default_factory=set)
    doc_commits: int = 0
    sample_commits: int = 0
    tool_commits: int = 0
    uncategorized_files: dict = field(default_factory=lambda: defaultdict(int))
    total_bpf_commits: int = 0
    # Location-based breakdown for kernel code
    kernel_bpf_commits: int = 0  # kernel/bpf/
    kernel_bpf_files: dict = field(default_factory=lambda: defaultdict(int))
    include_commits: int = 0     # include/
    include_files: dict = field(default_factory=lambda: defaultdict(int))
    net_commits: int = 0         # net/
    net_files: dict = field(default_factory=lambda: defaultdict(int))
    arch_commits: int = 0        # arch/*/net/ (JITs)
    arch_files: dict = field(default_factory=lambda: defaultdict(int))
    other_kernel_commits: int = 0
    other_kernel_files: dict = field(default_factory=lambda: defaultdict(int))


def analyze_version_range(start_tag: str, end_tag: str, sections: list[MaintainerSection]) -> VersionStats:
    """Analyze commit statistics for a version range"""
    stats = VersionStats(start_tag=start_tag, end_tag=end_tag)

    # Get all files touched in this range
    file_commits = get_files_touched_in_range(start_tag, end_tag)

    processed_files = set()

    for file_path, commit_count in file_commits.items():
        # Classify the file
        matched_sections = classify_file(file_path, sections)

        if not matched_sections:
            continue

        processed_files.add(file_path)
        stats.total_bpf_commits += commit_count

        # Categorize by type
        if is_selftest_file(file_path):
            stats.selftest_commits += commit_count
            stats.selftest_files.add(file_path)
        elif is_documentation_file(file_path):
            stats.doc_commits += commit_count
        elif is_sample_file(file_path):
            stats.sample_commits += commit_count
        elif is_tool_file(file_path):
            stats.tool_commits += commit_count
        else:
            # Kernel code - add to specific section stats
            for section_name in matched_sections:
                stats.section_stats[section_name]['files'][file_path] += commit_count
                stats.section_stats[section_name]['total_commits'] += commit_count

            # Location-based breakdown
            if file_path.startswith('kernel/bpf/'):
                stats.kernel_bpf_commits += commit_count
                stats.kernel_bpf_files[file_path] += commit_count
            elif file_path.startswith('include/'):
                stats.include_commits += commit_count
                stats.include_files[file_path] += commit_count
            elif file_path.startswith('net/'):
                stats.net_commits += commit_count
                stats.net_files[file_path] += commit_count
            elif file_path.startswith('arch/') and '/net/' in file_path:
                stats.arch_commits += commit_count
                stats.arch_files[file_path] += commit_count
            else:
                stats.other_kernel_commits += commit_count
                stats.other_kernel_files[file_path] += commit_count

    return stats


def print_version_stats(stats: VersionStats, top_n: int = 10, verbose: bool = False):
    """Print statistics for a version range"""
    print(f"\n{'='*70}")
    print(f"Version Range: {stats.start_tag} -> {stats.end_tag}")
    print(f"{'='*70}")

    print(f"\nTotal BPF-related commits: {stats.total_bpf_commits}")
    print(f"\nBreakdown by category:")
    print(f"  Selftests:      {stats.selftest_commits:5d} commits ({len(stats.selftest_files)} files)")
    print(f"  Documentation:  {stats.doc_commits:5d} commits")
    print(f"  Samples:        {stats.sample_commits:5d} commits")
    print(f"  Tools (non-selftest): {stats.tool_commits:5d} commits")

    kernel_commits = stats.total_bpf_commits - stats.selftest_commits - stats.doc_commits - stats.sample_commits - stats.tool_commits
    print(f"  Kernel code:    {kernel_commits:5d} commits")

    if not stats.section_stats:
        print("\n  (No kernel code changes in this range)")
        return

    # Sort sections by total commits
    sorted_sections = sorted(
        stats.section_stats.items(),
        key=lambda x: x[1]['total_commits'],
        reverse=True
    )

    print(f"\n{'-'*70}")
    print("Kernel Code Changes by MAINTAINERS Section:")
    print(f"{'-'*70}")

    for section_name, section_data in sorted_sections:
        total = section_data['total_commits']
        file_count = len(section_data['files'])
        print(f"\n  {section_name}")
        print(f"    Total commits: {total}, Files touched: {file_count}")

        # Show top files
        sorted_files = sorted(
            section_data['files'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]

        if sorted_files:
            print(f"    Top {min(top_n, len(sorted_files))} most changed files:")
            for file_path, count in sorted_files:
                # Shorten path for display
                short_path = file_path
                if len(short_path) > 50:
                    short_path = '...' + short_path[-47:]
                print(f"      {count:4d}  {short_path}")


def print_summary_table(all_stats: list[VersionStats]):
    """Print a summary table across all versions"""
    print("\n" + "="*90)
    print("SUMMARY TABLE: Commits by Category Across Versions")
    print("="*90)

    # Header
    print(f"\n{'Version Range':<20} {'Total':>8} {'Kernel':>8} {'Selftest':>9} {'Docs':>6} {'Samples':>8} {'Tools':>7}")
    print("-"*90)

    for stats in all_stats:
        kernel = stats.total_bpf_commits - stats.selftest_commits - stats.doc_commits - stats.sample_commits - stats.tool_commits
        version_range = f"{stats.start_tag}->{stats.end_tag}"
        print(f"{version_range:<20} {stats.total_bpf_commits:>8} {kernel:>8} {stats.selftest_commits:>9} {stats.doc_commits:>6} {stats.sample_commits:>8} {stats.tool_commits:>7}")

    # Totals
    print("-"*90)
    total_all = sum(s.total_bpf_commits for s in all_stats)
    total_kernel = sum(s.total_bpf_commits - s.selftest_commits - s.doc_commits - s.sample_commits - s.tool_commits for s in all_stats)
    total_selftest = sum(s.selftest_commits for s in all_stats)
    total_doc = sum(s.doc_commits for s in all_stats)
    total_sample = sum(s.sample_commits for s in all_stats)
    total_tool = sum(s.tool_commits for s in all_stats)
    print(f"{'TOTAL':<20} {total_all:>8} {total_kernel:>8} {total_selftest:>9} {total_doc:>6} {total_sample:>8} {total_tool:>7}")

    # Percentages
    print(f"{'PERCENTAGE':<20} {'100%':>8} {total_kernel*100//total_all:>7}% {total_selftest*100//total_all:>8}% {total_doc*100//total_all:>5}% {total_sample*100//total_all:>7}% {total_tool*100//total_all:>6}%")


def print_section_summary(all_stats: list[VersionStats]):
    """Print a summary of commits by MAINTAINERS section across versions"""
    print("\n" + "="*90)
    print("KERNEL CODE: Commits by MAINTAINERS Section (excluding selftests/docs/samples/tools)")
    print("="*90)

    # Aggregate across all versions
    section_totals = defaultdict(int)
    for stats in all_stats:
        for section_name, section_data in stats.section_stats.items():
            section_totals[section_name] += section_data['total_commits']

    # Sort by total
    sorted_sections = sorted(section_totals.items(), key=lambda x: x[1], reverse=True)

    print(f"\n{'Section':<55} {'Commits':>10}")
    print("-"*70)

    for section_name, total in sorted_sections:
        # Truncate long names
        display_name = section_name[:52] + '...' if len(section_name) > 55 else section_name
        print(f"{display_name:<55} {total:>10}")


def print_location_summary(all_stats: list[VersionStats], top_n: int = 5):
    """Print kernel code breakdown by location (kernel/bpf/, include/, net/, arch/, other)"""
    print("\n" + "="*90)
    print("KERNEL CODE: Breakdown by Location")
    print("="*90)

    # Aggregate across versions
    total_kernel_bpf = sum(s.kernel_bpf_commits for s in all_stats)
    total_include = sum(s.include_commits for s in all_stats)
    total_net = sum(s.net_commits for s in all_stats)
    total_arch = sum(s.arch_commits for s in all_stats)
    total_other = sum(s.other_kernel_commits for s in all_stats)
    total_all = total_kernel_bpf + total_include + total_net + total_arch + total_other

    if total_all == 0:
        print("\n  (No kernel code changes)")
        return

    # Summary table header
    print(f"\n{'Version Range':<18} {'kernel/bpf/':>12} {'include/':>10} {'net/':>8} {'arch/*/net/':>12} {'other':>8}")
    print("-"*75)

    for stats in all_stats:
        version_range = f"{stats.start_tag}->{stats.end_tag}"
        print(f"{version_range:<18} {stats.kernel_bpf_commits:>12} {stats.include_commits:>10} {stats.net_commits:>8} {stats.arch_commits:>12} {stats.other_kernel_commits:>8}")

    print("-"*75)
    print(f"{'TOTAL':<18} {total_kernel_bpf:>12} {total_include:>10} {total_net:>8} {total_arch:>12} {total_other:>8}")
    print(f"{'PERCENTAGE':<18} {total_kernel_bpf*100/total_all:>11.1f}% {total_include*100/total_all:>9.1f}% {total_net*100/total_all:>7.1f}% {total_arch*100/total_all:>11.1f}% {total_other*100/total_all:>7.1f}%")

    # Top files per location
    def aggregate_files(attr_name):
        files = defaultdict(int)
        for stats in all_stats:
            for f, c in getattr(stats, attr_name).items():
                files[f] += c
        return files

    locations = [
        ("kernel/bpf/", "kernel_bpf_files", total_kernel_bpf),
        ("include/", "include_files", total_include),
        ("net/", "net_files", total_net),
        ("arch/*/net/ (JITs)", "arch_files", total_arch),
        ("other", "other_kernel_files", total_other),
    ]

    for loc_name, attr_name, loc_total in locations:
        if loc_total == 0:
            continue
        files = aggregate_files(attr_name)
        sorted_files = sorted(files.items(), key=lambda x: x[1], reverse=True)[:top_n]

        print(f"\n  Top {min(top_n, len(sorted_files))} files in {loc_name} ({loc_total} commits, {loc_total*100/total_all:.1f}% of kernel):")
        for file_path, count in sorted_files:
            pct = count * 100 / loc_total
            short_path = file_path
            if len(short_path) > 50:
                short_path = '...' + short_path[-47:]
            print(f"    {count:4d} ({pct:5.1f}%)  {short_path}")


def print_hotspot_analysis(all_stats: list[VersionStats], top_n: int = 20):
    """Print the most frequently modified kernel files across all versions"""
    print("\n" + "="*90)
    print(f"HOTSPOT ANALYSIS: Top {top_n} Most Modified Kernel Files (across all versions)")
    print("="*90)

    # Aggregate file commits across all versions using location-based data (no double-counting)
    file_totals = defaultdict(int)
    for stats in all_stats:
        for file_dict in [stats.kernel_bpf_files, stats.include_files, stats.net_files,
                          stats.arch_files, stats.other_kernel_files]:
            for file_path, count in file_dict.items():
                file_totals[file_path] += count

    # Sort by total commits
    sorted_files = sorted(file_totals.items(), key=lambda x: x[1], reverse=True)[:top_n]

    total_commits = sum(file_totals.values())

    print(f"\n{'Commits':>8} {'%':>6}  {'File Path':<60}")
    print("-"*80)

    cumulative = 0
    for file_path, count in sorted_files:
        cumulative += count
        pct = count * 100 / total_commits if total_commits > 0 else 0
        cum_pct = cumulative * 100 / total_commits if total_commits > 0 else 0
        # Shorten path if needed
        display_path = file_path
        if len(display_path) > 60:
            display_path = '...' + display_path[-57:]
        print(f"{count:>8} {pct:>5.1f}%  {display_path:<60}")

    print("-"*80)
    print(f"Top {len(sorted_files)} files account for {cumulative} commits ({cumulative*100/total_commits:.1f}% of kernel code changes)")


def print_version_trends(all_stats: list[VersionStats]):
    """Show trends across versions"""
    print("\n" + "="*90)
    print("VERSION TRENDS: Change Rate Analysis")
    print("="*90)

    if len(all_stats) < 2:
        print("\nNeed at least 2 version ranges to show trends")
        return

    print("\n  Version range growth analysis:")
    for i, stats in enumerate(all_stats):
        kernel = stats.total_bpf_commits - stats.selftest_commits - stats.doc_commits - stats.sample_commits - stats.tool_commits
        if i > 0:
            prev_stats = all_stats[i-1]
            prev_kernel = prev_stats.total_bpf_commits - prev_stats.selftest_commits - prev_stats.doc_commits - prev_stats.sample_commits - prev_stats.tool_commits
            growth = ((stats.total_bpf_commits - prev_stats.total_bpf_commits) / prev_stats.total_bpf_commits * 100) if prev_stats.total_bpf_commits > 0 else 0
            kernel_growth = ((kernel - prev_kernel) / prev_kernel * 100) if prev_kernel > 0 else 0
            sign = "+" if growth >= 0 else ""
            ksign = "+" if kernel_growth >= 0 else ""
            print(f"  {stats.start_tag}->{stats.end_tag}: {stats.total_bpf_commits:4d} commits ({sign}{growth:.1f}%), kernel: {kernel:3d} ({ksign}{kernel_growth:.1f}%)")
        else:
            print(f"  {stats.start_tag}->{stats.end_tag}: {stats.total_bpf_commits:4d} commits (baseline), kernel: {kernel:3d}")

    # Show selftest ratio trend
    print("\n  Selftest to kernel ratio (selftests/kernel commits):")
    for stats in all_stats:
        kernel = stats.total_bpf_commits - stats.selftest_commits - stats.doc_commits - stats.sample_commits - stats.tool_commits
        ratio = stats.selftest_commits / kernel if kernel > 0 else 0
        print(f"  {stats.start_tag}->{stats.end_tag}: {ratio:.2f}x ({stats.selftest_commits} selftests / {kernel} kernel)")


def export_to_json(all_stats: list[VersionStats], output_file: str):
    """Export all statistics to JSON for further analysis"""
    data = {
        'versions': [],
        'summary': {
            'total_commits': 0,
            'kernel_commits': 0,
            'selftest_commits': 0,
            'doc_commits': 0,
            'sample_commits': 0,
            'tool_commits': 0,
        },
        'location_breakdown': {
            'kernel_bpf': 0,
            'include': 0,
            'net': 0,
            'arch': 0,
            'other': 0,
        },
        'sections': {},
        'hotspots': {},
    }

    # Aggregate data
    all_files = defaultdict(int)

    for stats in all_stats:
        kernel = stats.total_bpf_commits - stats.selftest_commits - stats.doc_commits - stats.sample_commits - stats.tool_commits
        version_data = {
            'range': f"{stats.start_tag}->{stats.end_tag}",
            'start_tag': stats.start_tag,
            'end_tag': stats.end_tag,
            'total_commits': stats.total_bpf_commits,
            'kernel_commits': kernel,
            'selftest_commits': stats.selftest_commits,
            'selftest_files': len(stats.selftest_files),
            'doc_commits': stats.doc_commits,
            'sample_commits': stats.sample_commits,
            'tool_commits': stats.tool_commits,
            'location_breakdown': {
                'kernel_bpf': stats.kernel_bpf_commits,
                'include': stats.include_commits,
                'net': stats.net_commits,
                'arch': stats.arch_commits,
                'other': stats.other_kernel_commits,
            },
            'sections': {}
        }

        for section_name, section_data in stats.section_stats.items():
            version_data['sections'][section_name] = {
                'total_commits': section_data['total_commits'],
                'files': dict(section_data['files'])
            }

            # Aggregate to overall sections
            if section_name not in data['sections']:
                data['sections'][section_name] = 0
            data['sections'][section_name] += section_data['total_commits']

        data['versions'].append(version_data)

        # Update summary
        data['summary']['total_commits'] += stats.total_bpf_commits
        data['summary']['kernel_commits'] += kernel
        data['summary']['selftest_commits'] += stats.selftest_commits
        data['summary']['doc_commits'] += stats.doc_commits
        data['summary']['sample_commits'] += stats.sample_commits
        data['summary']['tool_commits'] += stats.tool_commits

        # Update location breakdown
        data['location_breakdown']['kernel_bpf'] += stats.kernel_bpf_commits
        data['location_breakdown']['include'] += stats.include_commits
        data['location_breakdown']['net'] += stats.net_commits
        data['location_breakdown']['arch'] += stats.arch_commits
        data['location_breakdown']['other'] += stats.other_kernel_commits

        # Aggregate files for hotspots (using location data to avoid double-counting)
        for file_dict in [stats.kernel_bpf_files, stats.include_files, stats.net_files,
                          stats.arch_files, stats.other_kernel_files]:
            for file_path, count in file_dict.items():
                all_files[file_path] += count

    # Sort hotspots
    data['hotspots'] = dict(sorted(all_files.items(), key=lambda x: x[1], reverse=True))

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\nExported statistics to {output_file}")


# =============================================================================
# Symbol Dependency Analysis Functions
# =============================================================================

# C keywords and builtins to exclude from symbol references
C_KEYWORDS = {
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break',
    'continue', 'return', 'goto', 'sizeof', 'typeof', 'typeof_unqual',
    '__typeof__', '__typeof_unqual__', 'alignof', '_Alignof', '__alignof__',
    'offsetof', 'static_assert', '_Static_assert',
    # Common macros that look like functions
    'WARN', 'WARN_ON', 'WARN_ON_ONCE', 'WARN_ONCE', 'BUG', 'BUG_ON',
    'BUILD_BUG_ON', 'BUILD_BUG_ON_ZERO', 'BUILD_BUG_ON_MSG',
    'likely', 'unlikely', 'IS_ERR', 'IS_ERR_OR_NULL', 'PTR_ERR', 'ERR_PTR',
    'ERR_CAST', 'ARRAY_SIZE', 'FIELD_SIZEOF', 'container_of',
    'min', 'max', 'min_t', 'max_t', 'clamp', 'clamp_t', 'swap',
    'READ_ONCE', 'WRITE_ONCE', 'smp_load_acquire', 'smp_store_release',
    'smp_mb', 'smp_rmb', 'smp_wmb', 'barrier',
    'atomic_read', 'atomic_set', 'atomic_add', 'atomic_sub', 'atomic_inc',
    'atomic_dec', 'atomic_inc_return', 'atomic_dec_return',
    'atomic64_read', 'atomic64_set', 'atomic64_add', 'atomic64_sub',
    'atomic64_inc', 'atomic64_dec', 'atomic_long_read', 'atomic_long_set',
    'rcu_dereference', 'rcu_assign_pointer', 'rcu_read_lock', 'rcu_read_unlock',
    'spin_lock', 'spin_unlock', 'spin_lock_irq', 'spin_unlock_irq',
    'spin_lock_irqsave', 'spin_unlock_irqrestore', 'spin_lock_bh', 'spin_unlock_bh',
    'mutex_lock', 'mutex_unlock', 'mutex_trylock', 'mutex_lock_interruptible',
    'list_add', 'list_add_tail', 'list_del', 'list_del_init', 'list_move',
    'list_move_tail', 'list_empty', 'list_first_entry', 'list_last_entry',
    'list_for_each', 'list_for_each_entry', 'list_for_each_entry_safe',
    'hlist_add_head', 'hlist_del', 'hlist_del_init', 'hlist_empty',
    'hlist_for_each_entry', 'hlist_for_each_entry_safe', 'hlist_for_each_entry_rcu',
    'pr_err', 'pr_warn', 'pr_info', 'pr_debug', 'pr_notice', 'pr_alert',
    'pr_emerg', 'pr_crit', 'printk', 'dev_err', 'dev_warn', 'dev_info',
    'INIT_LIST_HEAD', 'INIT_HLIST_HEAD', 'INIT_HLIST_NODE',
    'GFP_KERNEL', 'GFP_ATOMIC', 'GFP_USER', '__GFP_ZERO',
    'THIS_MODULE', 'MODULE_LICENSE', 'MODULE_AUTHOR', 'MODULE_DESCRIPTION',
    'DEFINE_MUTEX', 'DEFINE_SPINLOCK', 'DECLARE_WAIT_QUEUE_HEAD',
    '__init', '__exit', '__user', '__kernel', '__iomem', '__percpu',
    'memset', 'memcpy', 'memmove', 'memcmp', 'strlen', 'strcmp', 'strncmp',
    'strcpy', 'strncpy', 'strcat', 'strncat',
    # Kernel allocation macros (inline wrappers)
    'kmalloc', 'kzalloc', 'kcalloc', 'kvmalloc', 'kvcalloc', 'kvzalloc',
    'krealloc', 'kmalloc_array', 'kmalloc_node', 'kzalloc_node',
    'devm_kmalloc', 'devm_kzalloc', 'devm_kcalloc',
    # User/kernel copy macros
    'copy_to_user', 'copy_from_user', '__copy_to_user', '__copy_from_user',
    'put_user', 'get_user', '__put_user', '__get_user',
    'clear_user', 'access_ok',
    # Per-CPU macros
    'per_cpu_ptr', 'this_cpu_ptr', 'raw_cpu_ptr', '__this_cpu_read', '__this_cpu_write',
    'this_cpu_read', 'this_cpu_write', 'this_cpu_inc', 'this_cpu_dec',
    'for_each_possible_cpu', 'for_each_online_cpu', 'num_possible_cpus',
    'DEFINE_PER_CPU', 'DECLARE_PER_CPU', 'DEFINE_PER_CPU_SHARED_ALIGNED',
    # RCU macros
    'rcu_dereference_protected', 'rcu_dereference_check', 'rcu_dereference_raw',
    'rcu_access_pointer', 'RCU_INIT_POINTER', 'rcu_replace_pointer',
    'lockdep_is_held', 'lockdep_assert_held', 'lock_is_held',
    # Common kernel macros
    'round_up', 'round_down', 'roundup', 'rounddown', 'roundup_pow_of_two',
    'DIV_ROUND_UP', 'ALIGN', 'IS_ALIGNED', 'PTR_ALIGN',
    'BIT', 'BIT_ULL', 'GENMASK', 'GENMASK_ULL', 'BITS_PER_LONG', 'BITS_PER_BYTE',
    'IS_ENABLED', 'IS_BUILTIN', 'IS_MODULE', 'IS_REACHABLE',
    'u64_to_user_ptr', 'make_bpfptr', 'bpfptr_to_u64',
    'xchg', 'cmpxchg', 'cmpxchg64', 'cmpxchg_relaxed', 'try_cmpxchg',
    'refcount_set', 'refcount_read', 'refcount_inc', 'refcount_dec',
    'refcount_dec_and_test', 'refcount_inc_not_zero',
    'local_irq_save', 'local_irq_restore', 'local_irq_disable', 'local_irq_enable',
    'preempt_disable', 'preempt_enable', 'preempt_enable_notrace',
    'cond_resched', 'might_sleep', 'schedule', 'schedule_timeout',
    'INIT_WORK', 'schedule_work', 'queue_work', 'cancel_work_sync',
    'mutex_init', 'spin_lock_init', 'rwlock_init',
    'va_start', 'va_end', 'va_arg', 'va_copy',
    'EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL', 'EXPORT_SYMBOL_NS', 'EXPORT_SYMBOL_NS_GPL',
    'late_initcall', 'early_initcall', 'module_init', 'module_exit',
    'subsys_initcall', 'fs_initcall', 'device_initcall', 'core_initcall',
    '__printf', '__scanf', '__attribute__', '__always_inline', '__noinline',
    '__aligned', '__packed', '__section', '__weak', '__maybe_unused',
    'noinline', 'inline', 'static_inline', 'notrace',
    'guard', 'scoped_guard', 'CLASS', 'DEFINE_GUARD', 'DEFINE_CLASS',
    'struct_size', 'flex_array_size', 'size_mul', 'size_add',
    'check_add_overflow', 'check_sub_overflow', 'check_mul_overflow',
    'llist_add', 'llist_del_all', 'llist_empty', 'llist_for_each_entry',
    'seq_puts', 'seq_putc', 'seq_printf', 'seq_write',  # seq_file inline wrappers
    'strscpy', 'strscpy_pad', 'strlcpy', 'strlcat',
    'is_power_of_2', 'ilog2', 'order_base_2', 'fls', 'ffs', '__ffs', '__fls',
    'defined', '__same_type', 'typecheck',
    # BPF-specific macros commonly used in JIT and verifier code
    'BPF_CLASS', 'BPF_OP', 'BPF_SRC', 'BPF_MODE', 'BPF_SIZE',
    'BPF_ALU64_REG', 'BPF_ALU64_IMM', 'BPF_ALU32_REG', 'BPF_ALU32_IMM',
    'BPF_MOV64_REG', 'BPF_MOV64_IMM', 'BPF_MOV32_REG', 'BPF_MOV32_IMM',
    'BPF_LD_IMM64', 'BPF_LD_MAP_FD', 'BPF_LDX_MEM', 'BPF_STX_MEM', 'BPF_ST_MEM',
    'BPF_JMP_REG', 'BPF_JMP_IMM', 'BPF_JMP32_REG', 'BPF_JMP32_IMM',
    'BPF_EXIT_INSN', 'BPF_EMIT_CALL', 'BPF_RAW_INSN', 'BPF_STMT', 'BPF_JUMP',
    'BPF_CALL_0', 'BPF_CALL_1', 'BPF_CALL_2', 'BPF_CALL_3', 'BPF_CALL_4', 'BPF_CALL_5',
    'BPF_CALL_IMM', 'DEFINE_BPF_ITER_FUNC',
    'BTF_ID', 'BTF_ID_LIST', 'BTF_ID_LIST_SINGLE', 'BTF_ID_FLAGS',
    'BTF_SET_START', 'BTF_SET_END', 'BTF_KFUNCS_START', 'BTF_KFUNCS_END',
    'BTF_SET8_START', 'BTF_SET8_END', 'BTF_TYPE_EMIT', 'BTF_INFO_KIND',
    '__bpf_kfunc', '__bpf_kfunc_start_defs', '__bpf_kfunc_end_defs',
    # JIT emit macros
    'EMIT', 'EMIT1', 'EMIT2', 'EMIT3', 'EMIT4', 'EMIT1_off32', 'EMIT2_off32',
    'emit', 'emit_insn', 'emit_a64_mov_i', 'emit_a64_mov_i64',
    # Common local variable names that look like function calls
    'func', 'prog', 'insn', 'reg', 'dst', 'src', 'off', 'imm', 'ctx', 'aux',
    'ret', 'err', 'len', 'val', 'ptr', 'buf', 'BUF', 'tmp', 'idx', 'cnt', 's',
}

# Patterns for BPF-internal symbols that should be excluded from "not exported" list
BPF_INTERNAL_PATTERNS = [
    r'^bpf_',           # BPF subsystem functions
    r'^btf_',           # BTF functions
    r'^__bpf_',         # Internal BPF helpers
    r'^__btf_',         # Internal BTF helpers
    r'^verifier',       # Verifier functions
    r'^verbose',        # Verifier verbose logging
    r'^check_',         # Verifier check functions
    r'^reg_',           # Register handling
    r'^tnum_',          # Tnum (tracked number) functions
    r'^htab_',          # Hash table internals
    r'^sock_map_',      # Sockmap internals
    r'^xdp_',           # XDP internals (unless exported)
    r'^cgroup_',        # cgroup helpers
    r'_elem_',          # Internal element handling
    r'^resolve_',       # Resolution functions
    r'^mark_',          # Marking functions
    r'^push_',          # Stack push functions
    r'^pop_',           # Stack pop functions
    r'^find_',          # Find functions (internal)
    r'^copy_map_',      # Map copy functions
]

# Regex patterns for export symbol declarations
EXPORT_SYMBOL_GPL_PATTERN = re.compile(
    r'EXPORT_SYMBOL_GPL\s*\(\s*(\w+)\s*\)'
)
EXPORT_SYMBOL_NS_GPL_PATTERN = re.compile(
    r'EXPORT_SYMBOL_NS_GPL\s*\(\s*(\w+)\s*,'
)
EXPORT_SYMBOL_PATTERN = re.compile(
    r'(?<!_)EXPORT_SYMBOL\s*\(\s*(\w+)\s*\)'
)
EXPORT_SYMBOL_NS_PATTERN = re.compile(
    r'(?<!_)EXPORT_SYMBOL_NS\s*\(\s*(\w+)\s*,'
)

# Pattern to find function calls (simplified)
FUNCTION_CALL_PATTERN = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

# Pattern to find static function definitions
STATIC_FUNC_PATTERN = re.compile(
    r'^\s*static\s+(?:inline\s+)?(?:__always_inline\s+)?(?:noinline\s+)?'
    r'(?:notrace\s+)?(?:__init\s+)?(?:__exit\s+)?'
    r'[a-zA-Z_][a-zA-Z0-9_*\s]+\s+(\w+)\s*\(',
    re.MULTILINE
)

# Pattern to find all function definitions (for local symbol detection)
FUNC_DEF_PATTERN = re.compile(
    r'^[a-zA-Z_][a-zA-Z0-9_*\s]+\s+(\w+)\s*\([^)]*\)\s*(?:\{|$)',
    re.MULTILINE
)


def scan_export_symbols(kernel_path: str) -> dict[str, ExportedSymbol]:
    """Scan kernel tree for all EXPORT_SYMBOL declarations"""
    exports = {}
    kernel_path = Path(kernel_path)

    # Directories to scan for exports
    scan_dirs = ['kernel', 'mm', 'fs', 'net', 'lib', 'drivers', 'arch', 'security', 'crypto', 'block', 'ipc']

    for scan_dir in scan_dirs:
        dir_path = kernel_path / scan_dir
        if not dir_path.exists():
            continue

        # Find all .c files
        for c_file in dir_path.rglob('*.c'):
            try:
                with open(c_file, 'r', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_no, line in enumerate(lines, 1):
                        # Check for GPL exports first (more specific patterns)
                        for match in EXPORT_SYMBOL_GPL_PATTERN.finditer(line):
                            symbol = match.group(1)
                            if symbol not in exports:
                                exports[symbol] = ExportedSymbol(
                                    name=symbol,
                                    export_type="GPL",
                                    defined_in=str(c_file.relative_to(kernel_path)),
                                    line=line_no
                                )

                        for match in EXPORT_SYMBOL_NS_GPL_PATTERN.finditer(line):
                            symbol = match.group(1)
                            if symbol not in exports:
                                exports[symbol] = ExportedSymbol(
                                    name=symbol,
                                    export_type="GPL",
                                    defined_in=str(c_file.relative_to(kernel_path)),
                                    line=line_no
                                )

                        # Check for non-GPL exports (but not if already GPL)
                        for match in EXPORT_SYMBOL_PATTERN.finditer(line):
                            symbol = match.group(1)
                            # Skip if this line also has GPL variant
                            if 'EXPORT_SYMBOL_GPL' not in line and symbol not in exports:
                                exports[symbol] = ExportedSymbol(
                                    name=symbol,
                                    export_type="non-GPL",
                                    defined_in=str(c_file.relative_to(kernel_path)),
                                    line=line_no
                                )

                        for match in EXPORT_SYMBOL_NS_PATTERN.finditer(line):
                            symbol = match.group(1)
                            if 'EXPORT_SYMBOL_NS_GPL' not in line and symbol not in exports:
                                exports[symbol] = ExportedSymbol(
                                    name=symbol,
                                    export_type="non-GPL",
                                    defined_in=str(c_file.relative_to(kernel_path)),
                                    line=line_no
                                )

            except Exception as e:
                pass  # Skip files we can't read

    return exports


def get_local_symbols(file_path: str) -> set[str]:
    """Get symbols defined locally in a file (static functions, local definitions)"""
    local_symbols = set()

    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # Find static function definitions
        for match in STATIC_FUNC_PATTERN.finditer(content):
            local_symbols.add(match.group(1))

        # Find all function definitions in this file
        for match in FUNC_DEF_PATTERN.finditer(content):
            local_symbols.add(match.group(1))

    except Exception:
        pass

    return local_symbols


def get_bpf_internal_symbols(kernel_path: str) -> set[str]:
    """Get all symbols defined in kernel/bpf/*.c files"""
    bpf_symbols = set()
    bpf_dir = Path(kernel_path) / 'kernel' / 'bpf'

    if not bpf_dir.exists():
        return bpf_symbols

    for c_file in bpf_dir.glob('*.c'):
        try:
            with open(c_file, 'r', errors='ignore') as f:
                content = f.read()

            # Find all function definitions
            for match in FUNC_DEF_PATTERN.finditer(content):
                bpf_symbols.add(match.group(1))

            # Also add exported symbols from BPF
            for match in EXPORT_SYMBOL_GPL_PATTERN.finditer(content):
                bpf_symbols.add(match.group(1))
            for match in EXPORT_SYMBOL_PATTERN.finditer(content):
                bpf_symbols.add(match.group(1))

        except Exception:
            pass

    return bpf_symbols


def extract_symbol_refs(file_path: str, exclude_symbols: set[str]) -> dict[str, list[int]]:
    """Extract all potential symbol references from a C file

    Returns dict of symbol -> list of line numbers where it's used
    """
    symbol_refs = defaultdict(list)

    try:
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()

        # Get local symbols to exclude
        local_syms = get_local_symbols(file_path)
        all_exclude = exclude_symbols | local_syms | C_KEYWORDS

        for line_no, line in enumerate(lines, 1):
            # Skip comments (simple heuristic)
            line_stripped = line.strip()
            if line_stripped.startswith('//') or line_stripped.startswith('*'):
                continue

            # Find all function calls
            for match in FUNCTION_CALL_PATTERN.finditer(line):
                symbol = match.group(1)

                # Skip excluded symbols
                if symbol in all_exclude:
                    continue

                # Skip if it looks like a type cast or declaration
                # Simple heuristic: skip if preceded by common type patterns
                pos = match.start()
                prefix = line[:pos].rstrip()
                if prefix.endswith(('struct', 'union', 'enum', 'typedef', '*', ')')):
                    continue

                symbol_refs[symbol].append(line_no)

    except Exception:
        pass

    return dict(symbol_refs)


def get_bpf_kernel_files(sections: list[MaintainerSection], kernel_path: str) -> dict[str, list[str]]:
    """Get BPF-related kernel .c files grouped by location category

    Returns dict with categories: kernel_bpf, net, arch_jit, other
    """
    kernel_path = Path(kernel_path)
    categories = {
        'kernel_bpf': [],
        'net': [],
        'arch_jit': [],
        'other': [],
    }

    # Collect all file patterns from BPF sections
    all_patterns = []
    for section in sections:
        all_patterns.extend(section.file_patterns)

    # Find matching .c files
    for c_file in kernel_path.rglob('*.c'):
        rel_path = str(c_file.relative_to(kernel_path))

        # Skip non-kernel code
        if any(rel_path.startswith(skip) for skip in
               ['tools/', 'samples/', 'Documentation/', 'scripts/', 'usr/']):
            continue

        # Check if this file matches any BPF pattern
        matched = False
        for pattern in all_patterns:
            if match_file_to_pattern(rel_path, pattern):
                matched = True
                break

        if not matched:
            continue

        # Categorize by location
        if rel_path.startswith('kernel/bpf/'):
            categories['kernel_bpf'].append(str(c_file))
        elif rel_path.startswith('net/'):
            categories['net'].append(str(c_file))
        elif rel_path.startswith('arch/') and '/net/' in rel_path:
            categories['arch_jit'].append(str(c_file))
        else:
            categories['other'].append(str(c_file))

    return categories


def analyze_symbol_dependencies(
    bpf_files: dict[str, list[str]],
    exports: dict[str, ExportedSymbol],
    bpf_internal: set[str],
    kernel_path: str
) -> dict[str, CategorySymbolDeps]:
    """Analyze symbol dependencies for each file category"""
    results = {}

    for category, files in bpf_files.items():
        cat_deps = CategorySymbolDeps(category=category, files_analyzed=len(files))

        for file_path in files:
            # Extract symbol references from this file
            refs = extract_symbol_refs(file_path, bpf_internal)
            rel_path = str(Path(file_path).relative_to(kernel_path))

            for symbol, line_nums in refs.items():
                if symbol in exports:
                    exp = exports[symbol]
                    if exp.export_type == "GPL":
                        if symbol not in cat_deps.gpl_symbols:
                            cat_deps.gpl_symbols[symbol] = SymbolUsage(
                                symbol=symbol,
                                export_type="GPL",
                                defined_in=exp.defined_in
                            )
                        cat_deps.gpl_symbols[symbol].used_by[rel_path].extend(line_nums)
                    else:
                        if symbol not in cat_deps.non_gpl_symbols:
                            cat_deps.non_gpl_symbols[symbol] = SymbolUsage(
                                symbol=symbol,
                                export_type="non-GPL",
                                defined_in=exp.defined_in
                            )
                        cat_deps.non_gpl_symbols[symbol].used_by[rel_path].extend(line_nums)
                else:
                    # Symbol is referenced but not exported
                    # Only track if it looks like a real kernel function
                    # (skip if it's just a local call we missed)
                    if symbol not in cat_deps.not_exported_symbols:
                        cat_deps.not_exported_symbols[symbol] = SymbolUsage(
                            symbol=symbol,
                            export_type="not-exported",
                            defined_in=""
                        )
                    cat_deps.not_exported_symbols[symbol].used_by[rel_path].extend(line_nums)

        results[category] = cat_deps

    return results


def is_bpf_internal_symbol(symbol: str) -> bool:
    """Check if a symbol looks like a BPF-internal function"""
    for pattern in BPF_INTERNAL_PATTERNS:
        if re.match(pattern, symbol):
            return True
    return False


def print_symbol_report(deps: dict[str, CategorySymbolDeps], top_n: int = 20):
    """Print formatted symbol dependency report"""
    category_names = {
        'kernel_bpf': 'kernel/bpf/ (Core BPF)',
        'net': 'net/ (Networking)',
        'arch_jit': 'arch/*/net/ (JIT Compilers)',
        'other': 'Other Locations',
    }

    print("\n" + "="*90)
    print("BPF SYMBOL DEPENDENCY ANALYSIS")
    print("="*90)

    # Collect all non-GPL symbols across categories for summary
    all_non_gpl = {}  # symbol -> {defined_in, categories: [cat -> files]}
    for cat_key, cat_deps in deps.items():
        for sym, usage in cat_deps.non_gpl_symbols.items():
            if sym not in all_non_gpl:
                all_non_gpl[sym] = {
                    'defined_in': usage.defined_in,
                    'categories': {},
                    'total_uses': 0
                }
            all_non_gpl[sym]['categories'][cat_key] = list(usage.used_by.keys())
            all_non_gpl[sym]['total_uses'] += sum(len(v) for v in usage.used_by.values())

    # Print executive summary
    print("\n" + "-"*90)
    print("EXECUTIVE SUMMARY: Non-GPL Symbols Requiring EXPORT_SYMBOL_GPL Upgrade")
    print("-"*90)
    print(f"\nTotal unique non-GPL exported symbols used by BPF: {len(all_non_gpl)}")
    print("\nThese symbols are currently EXPORT_SYMBOL (non-GPL) but would need")
    print("to become EXPORT_SYMBOL_GPL for BPF modularization.\n")

    # Sort by total uses
    sorted_non_gpl = sorted(all_non_gpl.items(), key=lambda x: x[1]['total_uses'], reverse=True)

    print(f"{'Symbol':<35} {'Defined In':<30} {'Uses':>6} {'Categories'}")
    print("-"*90)
    for sym, info in sorted_non_gpl[:top_n]:
        cats = ', '.join(sorted(info['categories'].keys()))
        defined = info['defined_in'][:30] if len(info['defined_in']) > 30 else info['defined_in']
        print(f"{sym:<35} {defined:<30} {info['total_uses']:>6} {cats}")

    if len(sorted_non_gpl) > top_n:
        print(f"\n... and {len(sorted_non_gpl) - top_n} more symbols (use --top to show more)")

    # Detailed per-category breakdown with file annotations
    print("\n" + "="*90)
    print("DETAILED BREAKDOWN BY CATEGORY")
    print("="*90)

    for cat_key, cat_deps in deps.items():
        cat_name = category_names.get(cat_key, cat_key)

        if not cat_deps.non_gpl_symbols:
            continue

        print(f"\n{'─'*90}")
        print(f"  {cat_name}")
        print(f"  Files analyzed: {cat_deps.files_analyzed}")
        print(f"{'─'*90}")

        # Group symbols by the files that use them
        file_to_symbols = defaultdict(list)
        for sym, usage in cat_deps.non_gpl_symbols.items():
            for file_path in usage.used_by.keys():
                file_to_symbols[file_path].append((sym, usage.defined_in))

        # Print file-centric view
        for file_path in sorted(file_to_symbols.keys()):
            symbols = file_to_symbols[file_path]
            print(f"\n  {file_path}:")
            for sym, defined_in in sorted(symbols, key=lambda x: x[0]):
                short_def = defined_in.split('/')[-1] if '/' in defined_in else defined_in
                print(f"    → {sym:<35} (from {short_def})")

    # Summary counts
    print("\n" + "="*90)
    print("CATEGORY TOTALS")
    print("="*90)
    print(f"\n{'Category':<30} {'Files':>8} {'Non-GPL Deps':>15} {'GPL Deps':>12}")
    print("-"*70)

    total_files = 0
    total_non_gpl = 0
    total_gpl = 0
    for cat_key, cat_deps in deps.items():
        cat_name = category_names.get(cat_key, cat_key)[:30]
        print(f"{cat_name:<30} {cat_deps.files_analyzed:>8} "
              f"{len(cat_deps.non_gpl_symbols):>15} "
              f"{len(cat_deps.gpl_symbols):>12}")
        total_files += cat_deps.files_analyzed
        total_non_gpl += len(cat_deps.non_gpl_symbols)
        total_gpl += len(cat_deps.gpl_symbols)

    print("-"*70)
    print(f"{'TOTAL':<30} {total_files:>8} {total_non_gpl:>15} {total_gpl:>12}")


def export_symbol_deps_to_json(deps: dict[str, CategorySymbolDeps], output_file: str):
    """Export symbol dependency analysis to JSON"""
    data = {
        'categories': {},
        'summary': {
            'total_files': 0,
            'total_gpl_symbols': 0,
            'total_non_gpl_symbols': 0,
            'total_not_exported': 0,
        },
        'all_non_gpl_symbols': {},
        'all_not_exported_symbols': {},
    }

    for cat_key, cat_deps in deps.items():
        cat_data = {
            'files_analyzed': cat_deps.files_analyzed,
            'gpl_symbols': {},
            'non_gpl_symbols': {},
            'not_exported_symbols': {},
        }

        for sym, usage in cat_deps.gpl_symbols.items():
            cat_data['gpl_symbols'][sym] = {
                'defined_in': usage.defined_in,
                'used_by': {f: lines for f, lines in usage.used_by.items()},
                'total_uses': sum(len(v) for v in usage.used_by.values()),
            }

        for sym, usage in cat_deps.non_gpl_symbols.items():
            cat_data['non_gpl_symbols'][sym] = {
                'defined_in': usage.defined_in,
                'used_by': {f: lines for f, lines in usage.used_by.items()},
                'total_uses': sum(len(v) for v in usage.used_by.values()),
            }
            # Add to global list
            if sym not in data['all_non_gpl_symbols']:
                data['all_non_gpl_symbols'][sym] = {
                    'defined_in': usage.defined_in,
                    'categories': [],
                    'total_uses': 0,
                }
            data['all_non_gpl_symbols'][sym]['categories'].append(cat_key)
            data['all_non_gpl_symbols'][sym]['total_uses'] += sum(len(v) for v in usage.used_by.values())

        for sym, usage in cat_deps.not_exported_symbols.items():
            uses = sum(len(v) for v in usage.used_by.values())
            if uses >= 2:  # Only significant symbols
                cat_data['not_exported_symbols'][sym] = {
                    'used_by': {f: lines for f, lines in usage.used_by.items()},
                    'total_uses': uses,
                }
                if sym not in data['all_not_exported_symbols']:
                    data['all_not_exported_symbols'][sym] = {
                        'categories': [],
                        'total_uses': 0,
                    }
                data['all_not_exported_symbols'][sym]['categories'].append(cat_key)
                data['all_not_exported_symbols'][sym]['total_uses'] += uses

        data['categories'][cat_key] = cat_data
        data['summary']['total_files'] += cat_deps.files_analyzed
        data['summary']['total_gpl_symbols'] += len(cat_deps.gpl_symbols)
        data['summary']['total_non_gpl_symbols'] += len(cat_deps.non_gpl_symbols)
        data['summary']['total_not_exported'] += len([s for s in cat_deps.not_exported_symbols.values()
                                                       if sum(len(v) for v in s.used_by.values()) >= 2])

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\nExported symbol analysis to {output_file}")


def run_symbol_analysis(args, sections: list[MaintainerSection]):
    """Run the symbol dependency analysis mode"""
    kernel_path = Path(args.maintainers).parent
    if not kernel_path.exists():
        kernel_path = Path('.')

    print("\n" + "="*50)
    print("BPF Symbol Dependency Analysis Mode")
    print("="*50)

    # Step 1: Scan for exported symbols
    print("\nStep 1: Scanning kernel for EXPORT_SYMBOL declarations...")
    exports = scan_export_symbols(str(kernel_path))
    gpl_count = sum(1 for e in exports.values() if e.export_type == "GPL")
    non_gpl_count = len(exports) - gpl_count
    print(f"  Found {len(exports)} exported symbols ({gpl_count} GPL, {non_gpl_count} non-GPL)")

    # Step 2: Get BPF internal symbols to exclude
    print("\nStep 2: Identifying BPF-internal symbols to exclude...")
    bpf_internal = get_bpf_internal_symbols(str(kernel_path))
    print(f"  Found {len(bpf_internal)} symbols in kernel/bpf/")

    # Step 3: Get BPF kernel files by category
    print("\nStep 3: Finding BPF-related kernel files...")
    bpf_files = get_bpf_kernel_files(sections, str(kernel_path))
    for cat, files in bpf_files.items():
        print(f"  {cat}: {len(files)} files")

    # Step 4: Analyze dependencies
    print("\nStep 4: Analyzing symbol dependencies...")
    deps = analyze_symbol_dependencies(bpf_files, exports, bpf_internal, str(kernel_path))

    # Step 5: Print report
    print_symbol_report(deps, top_n=args.top)

    # Step 6: Export to JSON if requested
    if args.symbol_json:
        export_symbol_deps_to_json(deps, args.symbol_json)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze BPF subsystem commit statistics across kernel versions'
    )
    parser.add_argument(
        '--start', '-s',
        default='6.9',
        help='Start kernel version (default: 6.9)'
    )
    parser.add_argument(
        '--end', '-e',
        default='6.13',
        help='End kernel version (default: 6.13)'
    )
    parser.add_argument(
        '--maintainers', '-m',
        default='MAINTAINERS',
        help='Path to MAINTAINERS file (default: MAINTAINERS)'
    )
    parser.add_argument(
        '--top', '-t',
        type=int,
        default=5,
        help='Number of top files to show per section (default: 5)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose output'
    )
    parser.add_argument(
        '--summary-only',
        action='store_true',
        help='Only show summary tables, skip per-version details'
    )
    parser.add_argument(
        '--json', '-j',
        type=str,
        default=None,
        metavar='FILE',
        help='Export statistics to JSON file for further analysis'
    )

    # Symbol dependency analysis mode
    parser.add_argument(
        '--symbols', '--deps',
        action='store_true',
        dest='symbols',
        help='Run symbol dependency analysis mode (analyze external symbol dependencies)'
    )
    parser.add_argument(
        '--symbol-json',
        type=str,
        default=None,
        metavar='FILE',
        help='Export symbol dependency analysis to JSON file'
    )

    args = parser.parse_args()

    print("BPF Subsystem Commit Statistics Analyzer")
    print("="*50)

    # Parse MAINTAINERS file
    print(f"\nParsing {args.maintainers}...")
    sections = parse_maintainers(args.maintainers)
    print(f"Found {len(sections)} BPF/XDP related sections:")
    for s in sections:
        print(f"  - {s.name} ({len(s.file_patterns)} file patterns)")

    # Symbol dependency analysis mode
    if args.symbols:
        run_symbol_analysis(args, sections)
        return

    # Normal commit statistics mode
    # Get version tags
    print(f"\nGetting version tags from v{args.start} to v{args.end}...")
    tags = get_version_tags(args.start, args.end)
    print(f"Found tags: {', '.join(tags)}")

    if len(tags) < 2:
        print("Error: Need at least 2 version tags to analyze")
        return

    # Analyze each version range
    all_stats = []
    for i in range(len(tags) - 1):
        start_tag = tags[i]
        end_tag = tags[i + 1]
        print(f"\nAnalyzing {start_tag} -> {end_tag}...")

        stats = analyze_version_range(start_tag, end_tag, sections)
        all_stats.append(stats)

        if not args.summary_only:
            print_version_stats(stats, top_n=args.top, verbose=args.verbose)

    # Print summary tables
    if len(all_stats) > 0:
        print_summary_table(all_stats)
        print_section_summary(all_stats)
        print_location_summary(all_stats, top_n=args.top)
        print_hotspot_analysis(all_stats, top_n=args.top * 4)  # Show more in hotspot
        print_version_trends(all_stats)

        # Export to JSON if requested
        if args.json:
            export_to_json(all_stats, args.json)


if __name__ == '__main__':
    main()
