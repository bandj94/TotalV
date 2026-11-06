# TotalV container image.
# Secrets are passed at runtime (docker run --env-file .env ...) and are never
# copied into the image. .dockerignore keeps .env out of the build context too.
FROM python:3.13-slim

# No .pyc files, unbuffered logs, and no pip cache left in the image.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies before copying the code, so this layer is reused
# when only the code changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY totalv ./totalv

# Run as an unprivileged user. The code stays owned by root, so the bot
# process can't modify it.
RUN useradd --create-home --shell /usr/sbin/nologin totalv
USER totalv

CMD ["python", "-m", "totalv"]
