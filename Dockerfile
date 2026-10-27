FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (FFmpeg, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY server.py updater.py custom_dns.py patch_channel.json app_icon.ico app_icon.png /app/

# Expose web port
EXPOSE 5050

ENV PORT=5050
ENV HOST=0.0.0.0
ENV HEADLESS=1

# Run web downloader server
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5050} --workers 1 --threads 4 --timeout 120 server:app"]
