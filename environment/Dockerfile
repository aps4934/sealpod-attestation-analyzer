FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

# Install system dependencies (including tmux and asciinema which are mandatory)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tmux \
    asciinema \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies lockfile
COPY requirements.lock /tmp/requirements.lock

# Install Python requirements at build time using the lockfile
RUN pip install --no-cache-dir --no-deps -r /tmp/requirements.lock

# Setup app directory
WORKDIR /app

# Copy challenge files (excluding solution/tests which are overlayed dynamically)
COPY app/ /app/
