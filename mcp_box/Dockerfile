FROM python:3.11-alpine

# TODO: pin versions before any production use
# numpy==1.26.4 pandas==2.2.2 etc.
RUN pip install --no-cache-dir numpy pandas matplotlib python-dateutil pytz

# Validate matplotlib Agg backend at build time to prevent silent runtime crashes
RUN python -c "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot"

# Create non-root sandbox user
RUN adduser -D -u 1000 sandboxuser

# Create workspace and grant ownership to sandboxuser
RUN mkdir -p /workspace && chown sandboxuser:sandboxuser /workspace

WORKDIR /workspace
USER sandboxuser
