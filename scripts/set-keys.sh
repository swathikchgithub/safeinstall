#!/usr/bin/env zsh
setopt err_exit pipe_fail nounset

AUTH_FILE="$HOME/.openclaw/agents/main/agent/auth-profiles.json"
BACKUP="${AUTH_FILE}.bak.$(date +%s)"

typeset -A KEYS
typeset -A ENV_MAP=(
  anthropic  ANTHROPIC_API_KEY
  google     GOOGLE_API_KEY
  groq       GROQ_API_KEY
  openai     OPENAI_API_KEY
  openrouter OPENROUTER_API_KEY
)

echo "═══ Paste each key (input hidden). Press Enter to skip. ═══"
for p in anthropic google groq openai openrouter; do
  print -n "  $p: "
  read -rs k
  print
  [[ -n "$k" ]] && KEYS[$p]="$k"
done

if (( ${#KEYS} == 0 )); then
  echo "No keys entered, aborting."
  exit 0
fi

echo ""
echo "═══ Validating against each provider's API ═══"
for p in ${(k)KEYS}; do
  k="${KEYS[$p]}"
  case $p in
    anthropic)
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://api.anthropic.com/v1/models" \
        -H "x-api-key: $k" -H "anthropic-version: 2023-06-01") ;;
    google)
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://generativelanguage.googleapis.com/v1beta/models?key=$k") ;;
    groq)
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://api.groq.com/openai/v1/models" -H "Authorization: Bearer $k") ;;
    openai)
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://api.openai.com/v1/models" -H "Authorization: Bearer $k") ;;
    openrouter)
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://openrouter.ai/api/v1/models" -H "Authorization: Bearer $k") ;;
  esac
  if [[ "$code" == "200" ]]; then
    echo "  $p: ✓ HTTP 200"
  else
    echo "  $p: ✗ HTTP $code — skipping"
    unset "KEYS[$p]"
  fi
done

(( ${#KEYS} == 0 )) && { echo "All keys failed. Aborting."; exit 1; }

echo ""
echo "═══ Writing ${#KEYS} key(s) ═══"
cp "$AUTH_FILE" "$BACKUP"
echo "  Backup: $BACKUP"

JQ_FILTER='.'
typeset -a JQ_ARGS
for p in ${(k)KEYS}; do
  JQ_FILTER="$JQ_FILTER | .profiles[\"${p}:default\"] = {type: \"api_key\", provider: \"${p}\", key: \$${p}}"
  JQ_ARGS+=(--arg "$p" "${KEYS[$p]}")
done

jq "${JQ_ARGS[@]}" "$JQ_FILTER" "$AUTH_FILE" > /tmp/auth-new.json

if ! jq -e '.profiles | length > 0' /tmp/auth-new.json > /dev/null; then
  echo "  ✗ Malformed result, restoring backup"
  cp "$BACKUP" "$AUTH_FILE"; exit 1
fi
mv /tmp/auth-new.json "$AUTH_FILE"
echo "  ✓ Written"

echo ""
echo "═══ Setting launchctl env vars ═══"
for p in ${(k)KEYS}; do
  launchctl setenv "${ENV_MAP[$p]}" "${KEYS[$p]}"
  echo "  ${ENV_MAP[$p]}: set"
done

for p in ${(k)KEYS}; do unset "KEYS[$p]"; done
unset k

echo ""
echo "═══ Restarting gateway ═══"
openclaw gateway restart

echo ""
echo "═══ Done ═══"
echo "Verify with: openclaw models status"
