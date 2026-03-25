#!/bin/bash

MAX_ITERATIONS=${1:-10}
MODEL=${2:-opus}

ITERATION=1
mkdir -p agent_logs

while [ $ITERATION -le $MAX_ITERATIONS ]; do
    COMMIT=$(git rev-parse --short=6 HEAD 2>/dev/null || echo "nocommit")
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    LOGFILE="agent_logs/agent_${COMMIT}_iter${ITERATION}_${TIMESTAMP}.log"
    PROMPTFILE=$(mktemp)

    cat > "$PROMPTFILE" << 'OUTER'
## Iteration Context

OUTER

    cat >> "$PROMPTFILE" << EOF
You are on **iteration ${ITERATION}/${MAX_ITERATIONS}**. Pace yourself:
- Pick ONE big milestone to complete this run
- Make meaningful, testable progress
- Commit your work before iteration ends
- Leave notes in PROGRESS.md for next iteration if needed
- Read PROGRESS.md first if it exists — it has notes from prior iterations

---

EOF

    cat AGENT_PROMPT.md >> "$PROMPTFILE"

    echo "========================================"
    echo "Iteration ${ITERATION}/${MAX_ITERATIONS} | ${COMMIT}"
    echo "Log: ${LOGFILE}"
    echo "========================================"
    echo "Working... (output appears when done)"
    echo ""

    claude -p "$(cat $PROMPTFILE)" \
        --model "$MODEL" \
        --allowedTools "Bash(*)" "Read(*)" "Write(*)" "Edit(*)" "Glob(*)" "Grep(*)" \
        --max-turns 50 \
        2>&1 | tee "$LOGFILE"

    rm -f "$PROMPTFILE"
    echo "Done iteration ${ITERATION}"
    echo ""

    ITERATION=$((ITERATION + 1))
done

echo "Completed ${MAX_ITERATIONS} iterations"
