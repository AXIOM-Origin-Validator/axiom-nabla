#!/usr/bin/env bash

PORT="${1:-6226}"
URL="http://localhost:$PORT"

echo "AXIOM Nabla Node Health"
echo "======================="

# Service status
if systemctl is-active --quiet axiom-nabla 2>/dev/null; then
    echo "Service:   RUNNING"
    UPTIME=$(systemctl show axiom-nabla --property=ActiveEnterTimestamp | cut -d= -f2)
    echo "Since:     $UPTIME"
else
    echo "Service:   STOPPED"
fi

# Dashboard
if curl -s --connect-timeout 2 "$URL/api/state" > /dev/null 2>&1; then
    DATA=$(curl -s "$URL/api/state")
    echo "Dashboard: OK"
    echo "$DATA" | python3 -c "
import json, sys
try:
    s = json.load(sys.stdin)
    if 'node' in s:
        n = s['node']
        print(f\"Tick:      {n.get('current_tick', '?')}\")
        print(f\"Peers:     {n.get('peer_count', '?')}\")
        print(f\"SMT:       {n.get('entry_count', '?')} entries\")
        print(f\"CC score:  {n.get('cc_score', '?')}\")
except:
    print('(could not parse status)')
" 2>/dev/null
else
    echo "Dashboard: NOT REACHABLE"
fi

# Disk
if [ -d "$HOME/.axiom" ]; then
    echo "Disk:      $(du -sh "$HOME/.axiom" 2>/dev/null | cut -f1)"
fi
