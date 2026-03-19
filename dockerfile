# Use a digest-pinned reference for the Python base image
FROM registry.access.redhat.com/ubi8/python-311@sha256:<REAL_DIGEST>

# Use a digest-pinned reference for the minimal Python base image
FROM registry.access.redhat.com/ubi8/python-311-minimal@sha256:<REAL_DIGEST>
