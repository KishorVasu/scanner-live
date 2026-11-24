# pip-audit scanner image. Built in CI; its digest goes into images.lock only after review.
# ponytail: pip-audit is installed by exact version without hashes; add a hashed requirements file when uv/pip-tools
# is approved (same open item as the API lockfile).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install pip-audit==2.10.1 && useradd --uid 10001 --no-create-home scanner
USER 10001
ENTRYPOINT []
