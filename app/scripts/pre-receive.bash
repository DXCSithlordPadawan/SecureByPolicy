#!/bin/bash
# Server-side Git Hook Shim

# Define the hardened image
IMAGE="git-policy-enforcer:1.0"

# Pass stdin to the containerized python orchestrator
cat | podman run --rm -i \
  --env SMTP_SERVER="smtp.internal.company.com" \
  --env MAIL_ENABLED=true \
  --security-opt no-new-privileges \
  --cap-drop=all \
  --read-only \
  --tmpfs /tmp \
  -v /etc/git-policy/rules:/app/rules:ro \
  $IMAGE python3 /app/orchestrator.py