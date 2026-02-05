FROM python:3.11-slim

WORKDIR /app

# Install OpenSSL
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Enable OpenSSL legacy provider for RC2, DES, etc.
RUN sed -i 's/default = default_sect/default = default_sect\nlegacy = legacy_sect/' /etc/ssl/openssl.cnf && \
    sed -i 's/\[default_sect\]/[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1/' /etc/ssl/openssl.cnf

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create temp directory
RUN mkdir -p /app/temp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
