############################
# Stage 1: Builder
############################
FROM python:3.11-slim AS builder

# Set working directory inside the image
WORKDIR /app

# Copy dependency file and install Python packages
COPY requirements.txt .

# Install all dependencies into a temporary location (/install)
RUN pip install --prefix=/install -r requirements.txt


############################
# Stage 2: Runtime
############################
FROM python:3.11-slim

# Set timezone to UTC for the whole container
ENV TZ=UTC

# Create working directory
WORKDIR /app

# Install system dependencies: cron + tzdata (timezone info)
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder stage into runtime image
COPY --from=builder /install /usr/local

# Copy application source code into the image
# (adjust list if you add more files later)
COPY main.py decrypt_seed.py totp_utils.py request_seed.py ./
COPY student_private.pem student_public.pem instructor_public.pem ./

# Cron script and configuration will be created in later steps:
#   - scripts/log_2fa_cron.py
#   - cron/2fa-cron
# For now we create the directories; we'll COPY files after we create them.
RUN mkdir -p /app/scripts /app/cron

# When cron file exists, Dockerfile lines will look like:
# COPY scripts/log_2fa_cron.py /app/scripts/log_2fa_cron.py
# COPY cron/2fa-cron /etc/cron.d/2fa-cron
# RUN chmod 0644 /etc/cron.d/2fa-cron && crontab /etc/cron.d/2fa-cron

# Create volume mount points for seed and cron output
RUN mkdir -p /data /cron

# Expose API port
EXPOSE 8080

# Start cron service and FastAPI app when container launches
CMD ["/bin/sh", "-c", "service cron start && uvicorn main:app --host 0.0.0.0 --port 8080"]
