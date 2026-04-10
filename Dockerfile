FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

WORKDIR /app/src

RUN python db_setup.py

EXPOSE 5000

# VULN: Running as root, debug mode enabled
CMD ["python", "app.py"]
