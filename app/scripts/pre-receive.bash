#!/bin/bash
# Server-side Git Hook Shim

# Define the hardened image.
# For production use, pin the image to its SHA256 digest for immutability (G-12):
#   export IMAGE_DIGEST="sha256:<digest>"
# Obtain the digest after building: podman inspect --format '{{.Digest}}' git-policy-enforcer:1.0
# Then set IMAGE_DIGEST in your server environment or systemd unit and redeploy this hook.
IMAGE="${IMAGE_DIGEST:+git-policy-enforcer@${IMAGE_DIGEST}}"
IMAGE="${IMAGE:-git-policy-enforcer:1.0}"

# Pass stdin to the containerized python orchestrator
cat | podman run --rm -i \
  --env SMTP_SERVER="smtp.internal.company.com" \
  --env MAIL_ENABLED=true \
  --security-opt no-new-privileges \
  --cap-drop=all \
  --read-only \
  --tmpfs /tmp \
  -v /etc/git-policy/rules:/app/rules:ro \
  "$IMAGE" python3 /app/orchestrator.py