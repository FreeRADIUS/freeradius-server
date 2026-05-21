#!/usr/bin/env python3
"""Generate text and markdown profiling reports from callgrind output files."""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict


def parse_thread_number(callgrind_file):
    with open(callgrind_file) as f:
        for line in f:
            if line.startswith('thread:'):
                return int(line.split()[1])
    return 0


def parse_summary_ir(callgrind_file):
    with open(callgrind_file) as f:
        for line in f:
            if line.startswith('summary:'):
                return int(line.split()[1])
    return 0


def run_callgrind_annotate(callgrind_file):
    result = subprocess.run(
        ['callgrind_annotate', '--auto=no', '--threshold=100', callgrind_file],
        capture_output=True, text=True
    )
    return result.stdout


def parse_module_entries(annotate_output):
    """Extract rlm_* and proto_load function rows from callgrind_annotate output."""
    entries = []
    for line in annotate_output.splitlines():
        if 'rlm_' not in line and 'proto_load' not in line:
            continue
        if not line.strip() or line.startswith('-') or line.startswith('='):
            continue

        ir_match = re.match(r'^\s*([\d,]+)\s+\(\s*([\d.]+)%\)', line)
        if not ir_match:
            continue

        func_match = re.search(r'([^/\s]+):(\w+)\s+\[([^\]]+)\]', line)
        if not func_match:
            continue

        entries.append({
            'ir': int(ir_match.group(1).replace(',', '')),
            'ir_pct': float(ir_match.group(2)),
            'function': func_match.group(2),
            'lib': os.path.basename(func_match.group(3)),
        })
    return entries


def fmt_ir(n):
    return f"{n:,}"


def generate_markdown(results_dir, thread_data, title):
    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Results:** `{results_dir}`")
    lines.append("")

    # Collect all unique function+lib pairs
    lib_to_funcs = defaultdict(set)
    for td in thread_data.values():
        for e in td['entries']:
            lib_to_funcs[e['lib']].add(e['function'])

    lines.append("## Functions Found")
    lines.append("")
    lines.append("| Function | Library |")
    lines.append("|---|---|")
    for lib in sorted(lib_to_funcs):
        funcs = ', '.join(f'`{f}`' for f in sorted(lib_to_funcs[lib]))
        lines.append(f"| {funcs} | `{lib}` |")
    lines.append("")

    lines.append("## CPU Share (Ir = Instructions Retired)")
    lines.append("")

    for thread_num, td in sorted(thread_data.items()):
        if not td['entries']:
            continue

        total_ir = td['total_ir']
        lines.append(f"### Thread {thread_num:02d} — Total: {fmt_ir(total_ir)} Ir")
        lines.append("")
        lines.append("| Function | Library | Ir | % of Thread |")
        lines.append("|---|---|---|---|")

        module_total = 0
        for e in sorted(td['entries'], key=lambda x: -x['ir']):
            lines.append(f"| `{e['function']}` | `{e['lib']}` | {fmt_ir(e['ir'])} | {e['ir_pct']:.2f}% |")
            module_total += e['ir']

        module_pct = (module_total / total_ir * 100) if total_ir else 0
        lines.append(f"| **Total** | | **{fmt_ir(module_total)}** | **{module_pct:.2f}%** |")
        lines.append("")

    all_module_ir = sum(e['ir'] for td in thread_data.values() for e in td['entries'])
    all_total_ir = sum(td['total_ir'] for td in thread_data.values())
    overall_pct = (all_module_ir / all_total_ir * 100) if all_total_ir else 0

    lines.append("## Takeaway")
    lines.append("")
    lines.append(
        f"`rlm_*` and `proto_load` combined account for **{overall_pct:.2f}% of total instructions** "
        f"across all threads ({fmt_ir(all_module_ir)} of {fmt_ir(all_total_ir)} Ir total)."
    )
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate profiling reports from callgrind results")
    parser.add_argument("results_dir", help="Directory containing callgrind.out.* files")
    parser.add_argument("--title", default=None, help="Report title")
    parser.add_argument("--text-output", default=None, help="Path for combined callgrind_annotate text report")
    parser.add_argument("--md-output", default=None, help="Path for markdown summary report")
    args = parser.parse_args()

    results_dir = args.results_dir
    if not os.path.isdir(results_dir):
        print(f"error: {results_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = sorted([
        os.path.join(results_dir, f)
        for f in os.listdir(results_dir)
        if re.match(r'callgrind\.out\.\d+(-\d+)?$', f) and os.path.getsize(os.path.join(results_dir, f)) > 0
    ])

    if not files:
        print(f"error: no callgrind.out.* files found in {results_dir}", file=sys.stderr)
        sys.exit(1)

    title = args.title or f"FreeRADIUS Callgrind Profile: {os.path.basename(os.path.normpath(results_dir))}"

    thread_data = {}
    text_sections = []

    for f in files:
        thread_num = parse_thread_number(f)
        total_ir = parse_summary_ir(f)
        print(f"  {os.path.basename(f)}: thread {thread_num:02d}, {total_ir:,} Ir", file=sys.stderr)

        annotate_output = run_callgrind_annotate(f)
        text_sections.append(f"{'='*80}\n{os.path.basename(f)} (thread {thread_num:02d})\n{'='*80}\n{annotate_output}")

        if thread_num not in thread_data:
            thread_data[thread_num] = {'total_ir': 0, 'entries': []}
        thread_data[thread_num]['total_ir'] += total_ir
        thread_data[thread_num]['entries'].extend(parse_module_entries(annotate_output))

    if args.text_output:
        with open(args.text_output, 'w') as out:
            out.write("\n\n".join(text_sections))
        print(f"text report -> {args.text_output}", file=sys.stderr)

    md = generate_markdown(results_dir, thread_data, title)

    if args.md_output:
        with open(args.md_output, 'w') as out:
            out.write(md)
        print(f"markdown report -> {args.md_output}", file=sys.stderr)
    else:
        print(md)


if __name__ == '__main__':
    main()
