# Hosted demo of guardrail-monitor: the real pipeline behind HTTP, fed sample
# Windows events. See web/app.py for what is real and what is simulated.
#
#   docker build -t gm-demo .
#   docker run --rm -p 8000:8000 gm-demo      # then open http://localhost:8000
#
# Render (and most hosts) inject $PORT; it defaults to 8000 here.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000 \
    GM_DEMO_DIR=/tmp/gm-demo

WORKDIR /app

COPY requirements.txt requirements-web.txt ./
RUN pip install -r requirements-web.txt

COPY gm ./gm
COPY web ./web
COPY policy.yaml policy.windows.yaml ./

# Never run a public service as root.
RUN useradd --create-home --uid 10001 gmdemo
USER gmdemo

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=4)"

# exec, so uvicorn is PID 1 and receives the platform's SIGTERM directly.
CMD ["sh", "-c", "exec uvicorn web.app:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
