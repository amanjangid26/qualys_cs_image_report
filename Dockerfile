FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY qualys_image_snow_report.py /app/
WORKDIR /app

ENTRYPOINT ["python3", "qualys_image_snow_report.py"]
