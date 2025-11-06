FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY ci/docker/rp_app.py .

EXPOSE 8080/tcp

CMD ["python", "/app/rp_app.py"]
