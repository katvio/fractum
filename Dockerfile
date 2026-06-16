FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f

WORKDIR /app

COPY setup.py README.md LICENSE bootstrap-linux.sh bootstrap-macos.sh bootstrap-windows.ps1 Dockerfile .dockerignore /app/
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY packages/ /app/packages/

# Install dependencies
RUN pip install --no-cache-dir -e .

# Create data directory and shares directory with proper permissions
RUN mkdir -p /data /app/shares && chmod 777 /data /app/shares

# Create non-root user
RUN adduser --disabled-password --gecos "" fractumuser

# Set proper permissions
RUN chown -R fractumuser:fractumuser /app /data
USER fractumuser

# Set app/shares as the share directory
# This matches where the application is writing the files
VOLUME ["/data", "/app/shares"]

# Set entrypoint
ENTRYPOINT ["fractum"]
CMD ["--help"]
