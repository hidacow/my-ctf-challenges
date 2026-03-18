FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy docmanager requirements and install
COPY docmanager/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy docmanager application
COPY docmanager /app

# Copy fixtures from deployment folder
COPY deployment/fixtures /app/docs/fixtures

# Copy init script
COPY deployment/init_minio.py /init_minio.py
COPY deployment/init_data.py /init_data.py

CMD ["python", "/init_minio.py"]
