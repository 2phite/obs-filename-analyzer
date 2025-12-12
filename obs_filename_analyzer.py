#!/usr/bin/env python3
"""
OBS Recording Filename Accuracy Analyzer

Analyzes whether OBS-generated filenames accurately represent their recording times.

Supports:
- Record files: filename = START time
- Replay Buffer files: filename = END time (detected by "Replay" prefix)
- Screenshots: filename = capture time

Usage:
    python obs_filename_analyzer.py [folder_path]

If no folder_path provided, uses current directory.

Output:
    Generates 'obs_filename_report.txt' in the analyzed folder.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path


def get_file_metadata(folder_path):
    """Get file metadata using PowerShell. Returns list of dicts."""
    import subprocess

    ps_script = f'''
    Get-ChildItem '{folder_path}' -File |
    Select-Object Name, Length, CreationTime, LastWriteTime |
    ConvertTo-Json
    '''

    result = subprocess.run(
        ['powershell', '-Command', ps_script],
        capture_output=True, text=True, encoding='utf-8'
    )

    if result.returncode != 0:
        print(f"Error getting file metadata: {result.stderr}")
        return []

    try:
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        print("Error parsing file metadata")
        return []


def get_video_durations(folder_path):
    """Get video durations using Windows Shell. Returns dict of {filename: duration_string}."""
    import subprocess

    ps_script = f'''
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace("{folder_path}")
    $results = @()
    foreach ($item in $folder.Items()) {{
        $duration = $folder.GetDetailsOf($item, 27)
        if ($duration) {{
            $results += [PSCustomObject]@{{
                Name = $folder.GetDetailsOf($item, 0)
                Duration = $duration
            }}
        }}
    }}
    $results | ConvertTo-Json
    '''

    result = subprocess.run(
        ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
        capture_output=True, text=True, encoding='utf-8'
    )

    if result.returncode != 0:
        print(f"Warning: Could not get some durations: {result.stderr}")
        return {}

    try:
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        return {d['Name']: d['Duration'] for d in data if d.get('Duration')}
    except (json.JSONDecodeError, TypeError):
        return {}


def parse_powershell_date(date_str):
    """Parse PowerShell's /Date(timestamp)/ format or datetime string."""
    if not date_str:
        return None

    match = re.search(r'/Date\((\d+)\)/', str(date_str))
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000)

    for fmt in ['%Y-%m-%dT%H:%M:%S', '%m/%d/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S']:
        try:
            return datetime.strptime(str(date_str)[:19], fmt)
        except ValueError:
            continue
    return None


def extract_datetime_from_filename(filename):
    """Extract datetime from OBS filename patterns."""
    match = re.search(r'(\d{4}-\d{2}-\d{2}) (\d{2}-\d{2}-\d{2})', filename)
    if match:
        date_str = f"{match.group(1)} {match.group(2)}"
        try:
            return datetime.strptime(date_str, '%Y-%m-%d %H-%M-%S')
        except ValueError:
            pass
    return None


def detect_obs_file_type(filename):
    """
    Detect OBS file type from filename.
    Returns: 'record', 'replay', 'screenshot', or 'unknown'
    """
    name_lower = filename.lower()
    if name_lower.startswith('replay '):
        return 'replay'
    elif name_lower.startswith('screenshot '):
        return 'screenshot'
    elif re.match(r'\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}', filename):
        return 'record'
    return 'unknown'


def parse_duration_string(dur_str):
    """Parse duration string like '00:19:22' to seconds."""
    if not dur_str:
        return None
    parts = dur_str.strip().split(':')
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        elif len(parts) == 2:
            return int(parts[0]) * 60 + int(parts[1])
    except ValueError:
        pass
    return None


def analyze_folder(folder_path):
    """Main analysis function."""
    folder_path = Path(folder_path).resolve()

    if not folder_path.exists():
        print(f"Error: Folder not found: {folder_path}")
        return

    print(f"Analyzing: {folder_path}")
    print("Getting file metadata...")

    files = get_file_metadata(str(folder_path))
    if not files:
        print("No files found or error reading folder.")
        return

    print(f"Found {len(files)} files. Getting video durations...")
    durations = get_video_durations(str(folder_path))
    print(f"Got durations for {len(durations)} files.")

    # Analyze each file
    results = []
    skipped = {'no_date': [], 'no_duration': [], 'not_video': []}

    for file in files:
        name = file.get('Name', '')

        # Skip non-video files
        if not any(name.lower().endswith(ext) for ext in ['.mkv', '.mp4', '.avi', '.mov', '.wmv']):
            skipped['not_video'].append(name)
            continue

        filename_dt = extract_datetime_from_filename(name)
        if not filename_dt:
            skipped['no_date'].append(name)
            continue

        duration_str = durations.get(name)
        duration_sec = parse_duration_string(duration_str)
        if duration_sec is None:
            skipped['no_duration'].append(name)
            continue

        last_write = parse_powershell_date(file.get('LastWriteTime'))
        if not last_write:
            continue

        # Detect file type and calculate accordingly
        file_type = detect_obs_file_type(name)

        if file_type == 'replay':
            # Replay: filename = END time, so expected_end = filename_time
            expected_end = filename_dt
            calculated_start = filename_dt - timedelta(seconds=duration_sec)
        else:
            # Record: filename = START time, so expected_end = filename + duration
            expected_end = filename_dt + timedelta(seconds=duration_sec)
            calculated_start = filename_dt

        diff_seconds = (last_write - expected_end).total_seconds()

        results.append({
            'filename': name,
            'file_type': file_type,
            'filename_datetime': filename_dt,
            'calculated_start': calculated_start,
            'duration': duration_sec,
            'duration_str': duration_str,
            'last_write': last_write,
            'expected_end': expected_end,
            'diff_seconds': diff_seconds,
        })

    # Generate report
    report_path = folder_path / 'obs_filename_report.txt'
    generate_report(results, skipped, report_path)
    print(f"\nReport saved to: {report_path}")


def generate_report(results, skipped, report_path):
    """Generate the analysis report."""

    with open(report_path, 'w', encoding='utf-8') as out:
        out.write("=" * 100 + "\n")
        out.write("OBS FILENAME ACCURACY ANALYSIS REPORT\n")
        out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write("=" * 100 + "\n\n")

        if not results:
            out.write("No video files with valid timestamps and durations found.\n")
            return

        # Count by type
        record_files = [r for r in results if r['file_type'] == 'record']
        replay_files = [r for r in results if r['file_type'] == 'replay']

        out.write("FILE TYPE BREAKDOWN\n")
        out.write("-" * 60 + "\n")
        out.write(f"Record files (filename = START time):  {len(record_files)}\n")
        out.write(f"Replay files (filename = END time):    {len(replay_files)}\n")
        out.write(f"Skipped (no date):  {len(skipped['no_date'])}\n")
        out.write(f"Skipped (no duration):  {len(skipped['no_duration'])}\n")
        out.write(f"Skipped (not video):  {len(skipped['not_video'])}\n\n")

        # Sort by absolute difference
        results.sort(key=lambda x: abs(x['diff_seconds']))

        diffs = [r['diff_seconds'] for r in results]
        avg_diff = sum(diffs) / len(diffs)
        avg_abs_diff = sum(abs(d) for d in diffs) / len(diffs)

        within_1s = sum(1 for d in diffs if abs(d) <= 1)
        within_2s = sum(1 for d in diffs if abs(d) <= 2)
        within_5s = sum(1 for d in diffs if abs(d) <= 5)
        within_10s = sum(1 for d in diffs if abs(d) <= 10)

        out.write("ACCURACY DISTRIBUTION (all files)\n")
        out.write("-" * 60 + "\n")
        out.write(f"Within  1 second:  {within_1s:3d} ({within_1s/len(results)*100:5.1f}%)\n")
        out.write(f"Within  2 seconds: {within_2s:3d} ({within_2s/len(results)*100:5.1f}%)\n")
        out.write(f"Within  5 seconds: {within_5s:3d} ({within_5s/len(results)*100:5.1f}%)\n")
        out.write(f"Within 10 seconds: {within_10s:3d} ({within_10s/len(results)*100:5.1f}%)\n\n")

        out.write("STATISTICS\n")
        out.write("-" * 60 + "\n")
        out.write(f"Average difference:     {avg_diff:+.1f} seconds\n")
        out.write(f"Average |difference|:   {avg_abs_diff:.1f} seconds\n")
        out.write(f"Maximum difference:     {max(diffs):+.0f} seconds\n")
        out.write(f"Minimum difference:     {min(diffs):+.0f} seconds\n\n")

        # Interpretation
        out.write("INTERPRETATION\n")
        out.write("-" * 60 + "\n")
        if within_5s / len(results) >= 0.90:
            out.write("EXCELLENT: 90%+ of filenames are accurate within 5 seconds.\n")
        elif within_10s / len(results) >= 0.90:
            out.write("GOOD: 90%+ of filenames are accurate within 10 seconds.\n")
        else:
            out.write("MIXED: Some files may have issues.\n")
        out.write("\n")

        # Outliers (files with large discrepancies)
        outliers = [r for r in results if abs(r['diff_seconds']) > 30]
        if outliers:
            out.write("=" * 100 + "\n")
            out.write(f"POTENTIAL ISSUES ({len(outliers)} files with >30s difference)\n")
            out.write("=" * 100 + "\n\n")
            out.write("Common causes:\n")
            out.write("- Corrupted metadata or DST boundary crossed\n")
            out.write("- Replay Buffer: 1-2 min delay is normal for longer captures (disk write time)\n\n")

            for r in sorted(outliers, key=lambda x: abs(x['diff_seconds']), reverse=True):
                out.write(f"  [{r['file_type'].upper()}] {r['filename']}\n")
                out.write(f"    Difference: {r['diff_seconds']:+.0f}s\n\n")

        # Detailed list
        out.write("=" * 100 + "\n")
        out.write("DETAILED FILE LIST (sorted by accuracy)\n")
        out.write("=" * 100 + "\n\n")

        out.write(f"{'Type':<8} {'Diff':<8} {'Duration':<10} {'Filename'}\n")
        out.write("-" * 95 + "\n")

        for r in results:
            diff_str = f"{r['diff_seconds']:+.0f}s"
            type_str = r['file_type'][:7]
            out.write(f"{type_str:<8} {diff_str:<8} {r['duration_str']:<10} {r['filename']}\n")

        # Skipped files
        if skipped['no_date'] or skipped['no_duration']:
            out.write("\n")
            out.write("=" * 100 + "\n")
            out.write("SKIPPED FILES\n")
            out.write("=" * 100 + "\n\n")

            if skipped['no_date']:
                out.write("No date pattern in filename:\n")
                for name in skipped['no_date']:
                    out.write(f"  - {name}\n")
                out.write("\n")

            if skipped['no_duration']:
                out.write("Could not read duration (possibly corrupted):\n")
                for name in skipped['no_duration']:
                    out.write(f"  - {name}\n")


if __name__ == '__main__':
    folder = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    analyze_folder(folder)
