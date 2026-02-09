FROM python:3.11-slim

WORKDIR /app

# Install OpenSSL and OpenJDK for JKS support
RUN apt-get update && apt-get install -y \
    openssl \
    openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Set Java environment
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="$JAVA_HOME/bin:$PATH"

# Enable OpenSSL legacy provider for RC2, DES, etc.
RUN sed -i 's/default = default_sect/default = default_sect\nlegacy = legacy_sect/' /etc/ssl/openssl.cnf && \
    sed -i 's/\[default_sect\]/[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1/' /etc/ssl/openssl.cnf

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip uninstall -y wheel && \
    pip install --no-cache-dir --upgrade pip wheel==0.46.2 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create temp directory
RUN mkdir -p /app/temp

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
