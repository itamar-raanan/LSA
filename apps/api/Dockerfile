FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY apps/api ./apps/api
RUN pip install --no-cache-dir .
ENV PYTHONPATH=/app/apps/api
CMD ["uvicorn", "lsa.main:app", "--host", "0.0.0.0", "--port", "8000"]

