# Whole app in one container: dashboard + the process sandbox that runs the attacks.
#   docker compose up --build   ->  http://127.0.0.1:8000
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    LD_SANDBOX=process LD_BIND=0.0.0.0 LD_PORT=8000
WORKDIR /app
COPY server.py engine.py sandbox_runner.py ./
COPY sample_app/ ./sample_app/
COPY static/ ./static/
# read-only for everyone (incl. the app user), but directories stay traversable (the old 0444-on-dirs broke this)
RUN chmod -R a-w,a+rX /app && find /app -type d -exec chmod 555 {} + && test -r /app/sample_app/vulnerable.py
USER 65534:65534
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["python", "server.py"]
