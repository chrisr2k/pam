FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (including openssl for .env decryption)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure entrypoint and shell scripts are executable
RUN chmod +x /app/entrypoint.sh /app/encrypt-env.sh

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user
RUN addgroup --system --gid 1001 pam && \
    adduser --system --uid 1001 --ingroup pam pam && \
    chown -R pam:pam /app
USER pam

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "pam.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]
