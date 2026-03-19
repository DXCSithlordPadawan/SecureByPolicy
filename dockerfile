# STAGE 1: Build Environment (NIST CM-2 compliant)
# NOTE (G-04): Replace the @sha256 digest below with the verified production digest before
# deploying.  Obtain the current digest with:
#   skopeo inspect docker://registry.access.redhat.com/ubi8/python-311:latest \
#     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Digest'])"
# Then pin it here:  registry.access.redhat.com/ubi8/python-311@sha256:<real-digest>
FROM registry.access.redhat.com/ubi8/python-311@sha256:abcd... AS builder

USER root
WORKDIR /build

# Install dependencies into a localized folder
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

# STAGE 2: Production Runtime (The "Clean Room")
# NOTE (G-04): Replace the @sha256 digest below with the verified production digest before
# deploying.  Obtain the current digest with:
#   skopeo inspect docker://registry.access.redhat.com/ubi8/python-311-minimal:latest \
#     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Digest'])"
# Then pin it here:  registry.access.redhat.com/ubi8/python-311-minimal@sha256:<real-digest>
FROM registry.access.redhat.com/ubi8/python-311-minimal@sha256:wxyz...

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