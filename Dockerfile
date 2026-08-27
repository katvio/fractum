FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f

WORKDIR /app

COPY setup.py README.md LICENSE TRADEMARK.md SECURITY.md bootstrap-linux.sh bootstrap-macos.sh bootstrap-windows.ps1 Dockerfile .dockerignore /app/
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY packages/ /app/packages/
COPY fractum-signing-key.asc /app/fractum-signing-key.asc

# Install dependencies — verify offline packages if present (M6)
# La verification GPG etait inoperante depuis la v1.4.1 : le fichier .asc a ete
# ajoute le 2026-07-15, ce qui a active cette branche pour la premiere fois,
# alors que l'image de base ne contient pas gpg et que la cle publique n'etait
# nulle part. L'image n'etait donc plus constructible du tout. On installe
# gnupg, on importe la cle du depot, et on verifie pour de bon.
RUN if [ -f packages/CHECKSUMS.sha256 ] && [ -f packages/CHECKSUMS.sha256.asc ]; then \
      apt-get update && apt-get install -y --no-install-recommends gnupg; \
      gpg --batch --quiet --import /app/fractum-signing-key.asc \
        || { echo "ERROR: cannot import the Fractum signing key"; exit 1; }; \
      gpg --batch --verify packages/CHECKSUMS.sha256.asc packages/CHECKSUMS.sha256 \
        || { echo "ERROR: Invalid GPG signature on packages"; exit 1; }; \
      apt-get purge -y gnupg && apt-get autoremove -y \
        && rm -rf /var/lib/apt/lists/* /root/.gnupg; \
    fi; \
    if [ -f packages/CHECKSUMS.sha256 ]; then \
      (cd packages && sha256sum --check CHECKSUMS.sha256 --strict --quiet) \
        || { echo "ERROR: Package hash mismatch"; exit 1; }; \
      pip install --no-cache-dir --no-index --find-links=packages -e .; \
    else \
      pip install --no-cache-dir -e .; \
    fi

# Create data directory and shares directory with proper permissions
RUN mkdir -p /data /app/shares && chmod 750 /data /app/shares

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
