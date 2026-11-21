# syntax=docker/dockerfile:1
# Screening-only gateway image: POST /v1/check (local_only) and GET /healthz.
# Built in CI only. The build context must contain models/distilbert (downloaded
# from the private S3 bucket by the workflow); the image is pushed only to private ECR.

ARG PYTHON_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# ── build stage: dependencies in a venv ───────────────────────────────
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
# CPU-only PyTorch (the "+cpu" build exists only on this index, so no CUDA libraries).
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0+cpu
COPY requirements-gateway.txt /tmp/requirements-gateway.txt
RUN pip install -r /tmp/requirements-gateway.txt \
 && pip uninstall -y pip setuptools wheel \
 && find /opt/venv -depth -type d -name "__pycache__" -exec rm -rf {} +

# ── runtime stage ─────────────────────────────────────────────────────
FROM ${PYTHON_IMAGE} AS runtime
RUN groupadd --system --gid 10001 gateway \
 && useradd --system --uid 10001 --gid gateway --no-create-home --shell /usr/sbin/nologin gateway
COPY --from=build /opt/venv /opt/venv

WORKDIR /app
# Only the gateway's modules: no agent, MCP, provenance, retrieval or evaluation code.
COPY app/main.py app/check_api.py app/gateway_state.py app/
COPY app/models/ app/models/
COPY app/services/ app/services/
COPY app/detectors/ app/detectors/
COPY models/distilbert/ models/distilbert/
RUN python -m compileall -q /app/app \
 && chmod -R a-w /app

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GATEWAY_PROFILE=aws \
    PIPELINE_MODE=local_only \
    LOCAL_CLASSIFIER_PATH=/app/models/distilbert \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HF_HOME=/tmp/hf \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--no-server-header"]
