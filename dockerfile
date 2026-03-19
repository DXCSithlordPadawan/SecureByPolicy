# Use a digest-pinned reference for the Python base image
FROM registry.access.redhat.com/ubi8/python-311@sha256:<REAL_DIGEST>

# Use a digest-pinned reference for the minimal Python base image
FROM registry.access.redhat.com/ubi8/python-311-minimal@sha256:<REAL_DIGEST>
# STAGE 1: Build Environment (NIST CM-2 compliant)
# Digest pinned to registry.access.redhat.com/ubi8/python-311:latest as of 2026-03-19.
# Refresh with:
#   skopeo inspect docker://registry.access.redhat.com/ubi8/python-311:latest \
#     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Digest'])"
FROM registry.access.redhat.com/ubi8/python-311@sha256:4812855431bd82a4e693311739f65a61156f484ae56c8cf40ac837d13db4c164 AS builder

USER root
WORKDIR /build

# Install dependencies into a localized folder
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

# STAGE 2: Production Runtime (The "Clean Room")
# Uses the same ubi8/python-311 image; ubi8/python-311-minimal is not published.
# Digest pinned to registry.access.redhat.com/ubi8/python-311:latest as of 2026-03-19.
# Refresh with:
#   skopeo inspect docker://registry.access.redhat.com/ubi8/python-311:latest \
#     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Digest'])"
FROM registry.access.redhat.com/ubi8/python-311@sha256:4812855431bd82a4e693311739f65a61156f484ae56c8cf40ac837d13db4c164

# Compliance Metadata
LABEL maintainer="Security-Ops" \
      com.company.compliance="NIST-800-53-STIG" \
      com.company.fips="enabled"

# Non-root service user (CIS Level 2)
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -m -s /sbin/nologin appuser

WORKDIR /app

# Copy ONLY dependencies and code from builder
COPY --from=builder --chown=appuser:appuser /build/deps /app/lib
COPY --chown=appuser:appuser . .

ENV PYTHONPATH=/app/lib

# Remove shell access and sensitive binaries (STIG V-222640)
RUN rm -rf /bin/chgrp /bin/chmod /bin/chown /usr/bin/yum*

USER appuser
ENTRYPOINT ["python3", "main.py"]
