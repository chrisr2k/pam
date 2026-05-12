FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user
RUN addgroup --system --gid 1001 pam && \
    adduser --system --uid 1001 --ingroup pam pam && \
    chown -R pam:pam /app
USER pam

EXPOSE 8000

CMD ["gunicorn", "pam.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]
