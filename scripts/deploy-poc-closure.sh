#!/usr/bin/env bash
set -euo pipefail
PROJECT='/Users/joaoluiskuntz/wso2mi/Projects/Demo/magalu-ciam-is73-poc'
cd "$PROJECT"
[[ "$(git rev-parse --show-toplevel)" == "$PROJECT" ]] || { echo 'Wrong Git root';exit 1; }
DC=(docker compose -p magalu-ciam73-s7lab -f compose.yaml -f compose.isolated.yaml -f compose.frontends.yaml)
"${DC[@]}" build demo
"${DC[@]}" up -d --no-deps demo
ready=false
for i in $(seq 1 30); do
  if curl -fsS --max-time 5 http://localhost:8180/m3/completion -o /dev/null 2>/dev/null; then
    ready=true; break
  fi
  sleep 2
done
[[ "$ready" == true ]] || { echo 'Dashboard not healthy';"${DC[@]}" logs --tail=80 demo;exit 1; }
echo 'LIVE UI: http://localhost:8180/m3/completion'
echo 'No WSO2 or database restart performed.'
