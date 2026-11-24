# Build context: repository root (needs scanners/images/images.lock).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN useradd --uid 10001 --no-create-home runner
WORKDIR /srv
COPY scan-runner/main.py scan-runner/runner.py ./
COPY scanners/images/images.lock /srv/images.lock
ENV SP_IMAGES_LOCK=/srv/images.lock
USER 10001
EXPOSE 8080
CMD ["python", "main.py"]
