FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /srv/broker
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt \
    && useradd --system --uid 10001 --no-create-home broker
COPY --chown=10001:10001 app.py run.py tokens.py keys.py ratelimit.py ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "run:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
