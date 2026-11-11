FROM python:3.12-slim
WORKDIR /project
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home ciampoc
COPY bootstrap ./bootstrap
COPY demo ./demo
COPY consent ./consent
COPY scripts ./scripts
RUN mkdir -p /project/generated && chown -R ciampoc:ciampoc /project
USER ciampoc
EXPOSE 8080
CMD ["uvicorn", "demo.main:app", "--host", "0.0.0.0", "--port", "8080"]
