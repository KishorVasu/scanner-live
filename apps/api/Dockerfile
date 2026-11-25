# Build context: repository root (needs libs/inventory). See deploy/docker-compose.yml.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Pango + a font for WeasyPrint (report PDFs). Distro packages from the pinned base's Debian release.
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --no-create-home app
WORKDIR /srv
COPY apps/api/requirements.lock .
RUN pip install --require-hashes -r requirements.lock
COPY libs/inventory /srv/libs/inventory
RUN pip install --no-deps /srv/libs/inventory
COPY apps/api/pyproject.toml apps/api/alembic.ini ./
COPY apps/api/app ./app
RUN pip install --no-deps .
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
