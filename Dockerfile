FROM python:3.11-slim

WORKDIR /workspace

RUN pip install --no-cache-dir fastapi uvicorn pydantic cryptography aiosqlite docker pytest pytest-asyncio

COPY . .
