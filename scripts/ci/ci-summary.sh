#!/bin/sh
#
# scripts/ci/ci-summary.sh
#
# Wrapped awk script that reads the test record file and emits a markdown
# summary to stdout, intended for piping into $GITHUB_STEP_SUMMARY.
#

set -eu

file=${1:-${CI_TEST_RECORD_FILE:-build/tests/results.tsv}}

if [ ! -s "$file" ]; then
    echo "## Test results"
    echo
    echo "_No results recorded._"
    exit 0
fi

awk -F'\t' '
{
    key = $1 "\t" $2
    cat[key] = $1
    name[key] = $2
    status[key] = $3
    logf[key] = $4
    seen[key] = NR  # last-wins
}
END {
    # Per-category counts
    for (k in seen) {
        c = cat[k]
        cats[c] = 1
        if (status[k] == "PASS") { cat_pass[c]++; total_pass++ }
        else if (status[k] == "FAIL") { cat_fail[c]++; total_fail++ }
        total++
    }

    # Header
    printf("## Test results\n\n")
    if (total_fail > 0) {
        printf("**%d / %d passed** (%d failed)\n\n", total_pass, total, total_fail)
    } else {
        printf("**%d / %d passed**\n\n", total_pass, total)
    }

    # Failure logs as collapsible blocks
    if (total_fail > 0) {
        printf("### Failure logs (last 20 lines)\n\n")
        for (k in seen) {
            if (status[k] != "FAIL") continue
            printf("<details><summary><code>%s/%s</code> &mdash; <code>%s</code></summary>\n\n",
                   cat[k], name[k], (logf[k] != "" ? logf[k] : "(no log captured)"))
            if (logf[k] != "") {
                printf("```\n")
                n = 0
                while ((getline line < logf[k]) > 0) buf[++n % 20] = line
                close(logf[k])
                start = (n < 20) ? 1 : n - 19
                for (j = start; j <= n; j++) print buf[j % 20]
                delete buf
                printf("```\n")
            } else {
                printf("_No log file recorded._\n")
            }
            printf("\n</details>\n\n")
        }
        printf("---\n\n")
    }

    # Per-category sections.  Categories with failures float to the top
    # via a single insertion sort; otherwise alphabetical.
    n = 0
    for (c in cats) ordered[++n] = c
    for (i = 2; i <= n; i++) {
        cur = ordered[i]; j = i - 1
        while (j >= 1) {
            a = ordered[j]; b = cur
            af = (cat_fail[a] ? 0 : 1); bf = (cat_fail[b] ? 0 : 1)
            if (af < bf || (af == bf && a < b)) break
            ordered[j+1] = ordered[j]; j--
        }
        ordered[j+1] = cur
    }

    for (i = 1; i <= n; i++) {
        c = ordered[i]
        cp = cat_pass[c] + 0; cf = cat_fail[c] + 0
        ct = cp + cf
        if (cf > 0)  printf("### %s (%d/%d, %d failed)\n\n", c, cp, ct, cf)
        else         printf("### %s (%d/%d)\n\n", c, cp, ct)
        printf("| Test | Status |\n|---|---|\n")
        # FAIL rows first, then PASS, each in test-execution order.
        for (k in seen) if (cat[k] == c && status[k] == "FAIL") emit(k)
        for (k in seen) if (cat[k] == c && status[k] == "PASS") emit(k)
        printf("\n")
    }
}

function emit(k) {
    printf("| `%s` | %s |\n", name[k], status[k])
}
' "$file"
