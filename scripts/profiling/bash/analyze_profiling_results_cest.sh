#!/bin/bash
###############################################################################
# analyze_profiling_results_cest.sh
#
# PURPOSE
#   Compare Callgrind cycle-estimate (CEst) cost across one or more profiling
#   runs. For each run (directory) it reports:
#     - total CEst
#     - per-pattern self-CEst for user-supplied function-name patterns
#     - top-N functions matching each pattern (NEW)
#     - a whole-program category breakdown: memset / printf / malloc / etc.
#       computed from the raw files, no QCachegrind needed (NEW)
#   With 2+ directories it prints a cross-run comparison footer, and with
#   --md it also writes a Markdown report mirroring the console output (NEW).
#
#   Self-cost totals match QCachegrind's "Cycle Estimation" exactly.
#
# WHY CEst IS COMPUTED HERE INSTEAD OF VIA callgrind_annotate --show=CEst
#   CEst is not a stored event in the callgrind.out files; it is a derived,
#   weighted combination of recorded cache/branch events. Some packaged builds
#   of callgrind_annotate (notably on macOS) do not expose CEst via --show,
#   so this script parses the raw files and applies the standard formula:
#
#       CEst = Ir
#            + 10  * (I1mr + D1mr + D1mw)     # L1 misses
#            + 100 * (ILmr + DLmr + DLmw)     # last-level misses
#            + 10  * (Bcm + Bim)              # branch mispredictions
#
#   This requires the run to have been profiled with --cache-sim=yes and
#   --branch-sim=yes.
#
# COST MODEL
#   Sums are SELF (exclusive) cost per function. Matches QCachegrind "Self".
#   Inclusive cost is NOT computed (that needs call-graph propagation).
#
# CALLGRIND FORMAT HANDLING (the three subtleties that matter)
#   1. EVENT COMPRESSION: trailing zero events are omitted; data lines do NOT
#      have fixed field count. With "positions: instr line" the first 2 fields
#      are positions and the rest are events; absent trailing events are 0.
#      Events read by FIXED position from the front (field 3 = Ir, ...),
#      never by counting back from NF.
#   2. INCLUSIVE CALL-COST LINES: the cost line after a "calls=" line is the
#      inclusive cost of that call, not self-cost; skipped to avoid ~24x
#      total inflation.
#   3. NAME COMPRESSION (shared symbol table): fn= and cfn= share ONE table.
#      A name may be first registered as a callee (cfn=) and only later appear
#      as a bare self-cost block (fn=(ID)). Names harvested from BOTH or
#      self-cost is under-attributed. Does NOT affect the run TOTAL.
#
#   Event order: Ir Dr Dw I1mr D1mr D1mw ILmr DLmr DLmw Bc Bcm Bi Bim
#   Field offsets (1-2 are positions):
#     Ir=$3 Dr=$4 Dw=$5 I1mr=$6 D1mr=$7 D1mw=$8 ILmr=$9 DLmr=$10 DLmw=$11
#     Bc=$12 Bcm=$13 Bi=$14 Bim=$15
#
# MAIN-FILE SELECTION
#   Profiling runs radiusd through a jlibtool wrapper with --trace-children,
#   so each dir has several callgrind.out.* files. Auto-selects, per dir, the
#   file with the largest Ir 'summary:' value (the real radiusd process).
#
# COMPATIBILITY
#   Stock macOS bash 3.2 — indexed arrays only (no declare -A).
#
# USAGE
#   ./analyze_profiling_results_cest.sh [--md <file>] [--top N] \
#       -d <dir1> [-d <dir2> ...] <pat1> [pat2 ...]
#
#     --md <file>  also write a Markdown report (console still prints)
#     --top N      top-N functions per pattern (default 10)
#
# PATTERN MATCHING
#   Each pattern is a case-insensitive SUBSTRING (e.g. 'prefix1' also matches
#   prefix1_pool, prefix1_init, ...).
#
# EXAMPLE
#   ./analyze_profiling_results_cest.sh --md report.md --top 6 \
#       -d /path/to/build1/prof-results \
#       -d /path/to/build2/prof-results \
#       prefix1 prefix2
###############################################################################


# ===========================================================================
# CONFIG: whole-program cost categories  (EDIT ME)
#   "Label|ERE-regex" matched case-insensitively against the resolved
#   function name. First matching category (in listed order) wins, so order
#   most-specific first. These are libc/libcrypto/allocator groupings from
#   observed FreeRADIUS profiles; adjust freely.
# ===========================================================================
CATEGORIES=(
  "memset (zeroing)|memset"
  "memmove/memcpy|mem(move|cpy)"
  "printf / string fmt|(printf_buffer|vsnprintf|vasprintf|itoa|snprintf_chk)"
  "malloc family (libc)|(^malloc$|^free$|_int_malloc|_int_free|_int_realloc|^realloc$)"
  "sha256 / crypto|(sha256|evp_|openssl_|crypto_|hmac|kdf_|evp_md)"
  "pthread / locking|(pthread_rwlock|pthread_getspecific|thread_)"
)


# ---------------------------------------------------------------------------
# PHASE 1: Parse arguments
#   --md <file> and --top N consumed first (long flags), then -d <dir>
#   (repeatable), then remaining args = function-name patterns.
# ---------------------------------------------------------------------------
MD_FILE=""
TOPN=10
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --md)  MD_FILE="$2"; shift 2 ;;
    --top) TOPN="$2";    shift 2 ;;
    *)     ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]}"

DIRS=()
while getopts "d:" opt; do
  case "$opt" in
    d) DIRS+=("$OPTARG") ;;
    *) echo "Usage: $0 [--md <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]" >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

[ ${#DIRS[@]} -eq 0 ] && DIRS=(".")
[ $# -lt 1 ] && { echo "Usage: $0 [--md <file>] [--top N] -d <dir> [-d <dir> ...] <pat> [pat ...]" >&2; exit 1; }
PATTERNS=("$@")
NP=${#PATTERNS[@]}

CAT_CFG=""
for c in "${CATEGORIES[@]}"; do
  if [ -z "$CAT_CFG" ]; then CAT_CFG="$c"; else CAT_CFG="$CAT_CFG;$c"; fi
done


# ---------------------------------------------------------------------------
# PHASE 2: Helper — pick the "real radiusd" file in a directory
# ---------------------------------------------------------------------------
pick_main_file() {
  local dir="$1"; local best="" bestval=-1 f val
  for f in "$dir"/callgrind.out.*; do
    [ -e "$f" ] || continue
    val=$(grep -m1 '^summary:' "$f" | awk '{print $2}')
    [ -z "$val" ] && continue
    if [ "$val" -gt "$bestval" ] 2>/dev/null; then
      bestval="$val"; best="$f"
    fi
  done
  echo "$best"
}


# ---------------------------------------------------------------------------
# PHASE 3: Cross-run accumulators (bash 3.2 compatible — indexed arrays only)
#   D_LABEL/D_MAIN/D_TOTAL[idx], D_PSUM[idx*NP+p], D_CAT[idx],
#   D_TOP[idx*NP+p]
# ---------------------------------------------------------------------------
D_LABEL=(); D_MAIN=(); D_TOTAL=(); D_PSUM=(); D_CAT=(); D_TOP=()


# ===========================================================================
# PHASE 4: Core parser (shared awk). Emits:
#   TOTAL <n>
#   PAT <patIndex> <cest> <pct>
#   FN  <self_cest> <pct> <name>
#   CAT <catIndex>\t<label>\t<cest>\t<pct>
# ===========================================================================
run_parser() {
  local main="$1"
  awk -v patlist="${PATTERNS[*]}" -v catcfg="$CAT_CFG" '
    function cest(ir,i1,d1r,d1w,ilm,dlr,dlw,bcm,bim){
      return ir+10*(i1+d1r+d1w)+100*(ilm+dlr+dlw)+10*(bcm+bim) }
    function resolve(s,   id,rest){
      if (match(s, /^\([0-9]+\)/)) {
        id=substr(s, RSTART+1, RLENGTH-2)
        rest=substr(s, RSTART+RLENGTH); sub(/^[ \t]+/,"",rest)
        if (rest != "") name[id]=rest
        return (id in name) ? name[id] : ""
      }
      return s
    }
    BEGIN{
      np=split(patlist,P," ")
      nc=split(catcfg, CL, ";"); ncat=0
      for(k=1;k<=nc;k++){
        if(CL[k]=="") continue
        pos=index(CL[k],"|"); if(pos==0) continue
        ncat++; CLAB[ncat]=substr(CL[k],1,pos-1); CRE[ncat]=tolower(substr(CL[k],pos+1))
      }
    }
    /^fn=/    { fn=resolve(substr($0,4)); next }
    /^cfn=/   { resolve(substr($0,5)); next }
    /^calls=/ { skipnext=1; next }
    /^cob=/   { next }
    /^cfi=/ || /^cfl=/ { next }
    /^[0-9a-fx*+-]/ {
      if (NF<3 || $3 !~ /^[0-9]+$/) next
      if (skipnext) { skipnext=0; next }
      ir =$3+0
      i1 =(NF>=6 ?$6 :0)+0; d1r=(NF>=7 ?$7 :0)+0; d1w=(NF>=8 ?$8 :0)+0
      ilm=(NF>=9 ?$9 :0)+0; dlr=(NF>=10?$10:0)+0; dlw=(NF>=11?$11:0)+0
      bcm=(NF>=13?$13:0)+0; bim=(NF>=15?$15:0)+0
      c=cest(ir,i1,d1r,d1w,ilm,dlr,dlw,bcm,bim)
      total+=c
      if(fn!=""){
        self[fn]+=c
        lf=tolower(fn)
        for(i=1;i<=np;i++) if(index(lf,tolower(P[i]))) psum[i]+=c
        for(k=1;k<=ncat;k++) if(lf ~ CRE[k]){ csum[k]+=c; break }
      }
      next
    }
    { skipnext=0 }
    END{
      printf "TOTAL %d\n", total
      for(i=1;i<=np;i++) printf "PAT %d %d %.4f\n", i, psum[i]+0, (total?psum[i]/total*100:0)
      for(f in self) printf "FN %d %.4f %s\n", self[f], (total?self[f]/total*100:0), f
      for(k=1;k<=ncat;k++) printf "CAT %d\t%s\t%d\t%.4f\n", k, CLAB[k], csum[k]+0, (total?csum[k]/total*100:0)
    }' "$main"
}


# ---------------------------------------------------------------------------
# PHASE 5: Per-directory report
# ---------------------------------------------------------------------------
report_dir() {
  local idx="$1" dir="$2"
  local main; main=$(pick_main_file "$dir")
  [ -z "$main" ] && { echo "No usable callgrind.out.* in $dir" >&2; return 1; }

  local out; out=$(run_parser "$main")
  local total; total=$(echo "$out" | awk '/^TOTAL/{print $2}')

  D_LABEL[$idx]="$dir"; D_MAIN[$idx]="$(basename "$main")"; D_TOTAL[$idx]="$total"

  echo "==================================================="
  echo "Directory: $dir"
  echo "Main file: $(basename "$main")"
  echo "total CEst: $total"
  echo "---------------------------------------------------"

  # 5.1 per-pattern sums
  local p name pct cst
  for ((p=0; p<NP; p++)); do
    name="${PATTERNS[$p]}"
    read -r cst pct <<< "$(echo "$out" | awk -v i=$((p+1)) '$1=="PAT" && $2==i {print $3, $4}')"
    printf '%-26s CEst: %s  (%s%%)\n' "$name" "$cst" "$pct"
    D_PSUM[$((idx*NP + p))]="$cst"
  done
  echo

  # 5.2 top-N per pattern (NEW)
  for ((p=0; p<NP; p++)); do
    name="${PATTERNS[$p]}"
    echo "--- Top $TOPN functions matching '$name' ---"
    local block
    block=$(echo "$out" | awk -v pat="$name" '
      $1=="FN" { c=$2; pc=$3; $1="";$2="";$3=""; sub(/^ +/,""); nm=$0
        if(index(tolower(nm),tolower(pat))) printf "%d\t%s\t%s\n", c, pc, nm }' \
      | sort -rn | head -n "$TOPN" \
      | awk -F'\t' '{printf "%-36s %11d  %6.2f%%\n", $3, $1, $2}')
    [ -z "$block" ] && block="  (no matching functions)"
    echo "$block"
    echo
    D_TOP[$((idx*NP + p))]="$block"
  done

  # 5.3 category breakdown (NEW)
  echo "--- Where the cost goes (categories) ---"
  local catblock
  catblock=$(echo "$out" | awk -F'\t' '$1 ~ /^CAT/ {printf "%-24s %11d  %6.2f%%\n", $2, $3, $4}')
  echo "$catblock"
  echo
  D_CAT[$idx]="$catblock"
}


# ---------------------------------------------------------------------------
# PHASE 6: Drive reports
# ---------------------------------------------------------------------------
i=0
for d in "${DIRS[@]}"; do report_dir "$i" "$d"; i=$((i+1)); done


# ---------------------------------------------------------------------------
# PHASE 7: Console comparison footer (2+ dirs)
# ---------------------------------------------------------------------------
if [ ${#DIRS[@]} -ge 2 ]; then
  base_total="${D_TOTAL[0]}"
  echo "==================================================="
  echo "COMPARISON  (baseline = dir 0: $(basename "${D_LABEL[0]}"))"
  echo "==================================================="
  j=0
  while [ "$j" -lt "${#DIRS[@]}" ]; do
    echo "[dir $j] ${D_LABEL[$j]}"
    t="${D_TOTAL[$j]}"
    if [ "$j" -eq 0 ]; then
      printf '  %-14s %18s %12s\n' "total CEst" "$t" "-"
    else
      d=$(echo "scale=2; ($t-$base_total)*100/$base_total" | bc)
      printf '  %-14s %18s %11s%%\n' "total CEst" "$t" "$d"
    fi
    p=0
    for PAT in "${PATTERNS[@]}"; do
      v="${D_PSUM[$((j*NP + p))]:-0}"; bv="${D_PSUM[$p]:-0}"
      if [ "$j" -eq 0 ] || [ "$bv" -eq 0 ]; then
        printf '  %-14s %18s %12s\n' "$PAT" "$v" "-"
      else
        d=$(echo "scale=2; ($v-$bv)*100/$bv" | bc)
        printf '  %-14s %18s %11s%%\n' "$PAT" "$v" "$d"
      fi
      p=$((p+1))
    done
    echo
    j=$((j+1))
  done
fi


# ---------------------------------------------------------------------------
# PHASE 8: Markdown report (only with --md <file>)
# ---------------------------------------------------------------------------
if [ -n "$MD_FILE" ]; then
  base_total="${D_TOTAL[0]}"; delta=""
  [ ${#DIRS[@]} -ge 2 ] && delta=$(echo "scale=1; (${D_TOTAL[1]}-$base_total)*100/$base_total" | bc)
  {
    echo "# Callgrind CEst Profiling Assessment"
    echo
    echo "_Generated by analyze_profiling_results_cest.sh. Tables are computed"
    echo "from callgrind.out.* files_"
    echo
    echo "## Headline Results"
    echo
    if [ ${#DIRS[@]} -ge 2 ]; then
      echo "- Baseline (dir 0): \`${D_MAIN[0]}\` — total CEst ${D_TOTAL[0]}"
      echo "- Compared (dir 1): \`${D_MAIN[1]}\` — total CEst ${D_TOTAL[1]} (${delta}% vs baseline)"
      echo
    fi
    echo "<!-- TODO: short explanation. Example: On a matched, sustained"
    echo "workload, the dir-1 build runs ~X% cheaper in total, but its"
    echo "<pattern> self-cost is higher/lower. The net change does/does not"
    echo "come from <pattern> itself. -->"
    echo
    echo "## Per-Pattern Self CEst"
    echo
    echo '```'
    printf '%-26s' "Pattern"
    for ((k=0; k<${#DIRS[@]}; k++)); do printf ' %18s %8s' "dir$k CEst" "dir$k %"; done
    echo
    p=0
    for PAT in "${PATTERNS[@]}"; do
      printf '%-26s' "$PAT"
      for ((k=0; k<${#DIRS[@]}; k++)); do
        v="${D_PSUM[$((k*NP + p))]:-0}"; pc="0.00"
        [ "${D_TOTAL[$k]}" -gt 0 ] 2>/dev/null && pc=$(echo "scale=2; $v*100/${D_TOTAL[$k]}" | bc)
        printf ' %18s %7s%%' "$v" "$pc"
      done
      echo; p=$((p+1))
    done
    echo '```'
    echo
    echo "## Where the Cost Goes (whole-program categories)"
    echo
    for ((k=0; k<${#DIRS[@]}; k++)); do
      echo "**dir $k — ${D_LABEL[$k]}** (\`${D_MAIN[$k]}\`)"
      echo
      echo '```'
      echo "Category                  Self CEst   Self %"
      echo "------------------------  ----------  ------"
      echo "${D_CAT[$k]}"
      echo '```'
      echo
    done
    echo "## Top $TOPN Functions per Pattern"
    echo
    p=0
    for PAT in "${PATTERNS[@]}"; do
      echo "### Pattern: \`$PAT\`"
      echo
      for ((k=0; k<${#DIRS[@]}; k++)); do
        echo "**dir $k** (\`${D_MAIN[$k]}\`, total ${D_TOTAL[$k]})"
        echo
        echo '```'
        echo "Function                              Self CEst   Self %"
        echo "------------------------------------  -----------  ------"
        echo "${D_TOP[$((k*NP + p))]:-  (none)}"
        echo '```'
        echo
      done
      p=$((p+1))
    done
    echo "## Methodology"
    echo
    echo "CEst = Ir + 10*(L1 misses) + 100*(LL misses) + 10*(branch mispredicts)."
    echo "Self-cost only (QCachegrind \"Self\" column); inclusive cost not computed."
    echo "Parser handles inclusive call-cost lines, event compression, and the"
    echo "shared fn=/cfn= symbol table; run totals match QCachegrind exactly."
    echo "Category definitions are editable in the CATEGORIES array at the top."
  } > "$MD_FILE"
  echo "Markdown report written to: $MD_FILE"
fi
