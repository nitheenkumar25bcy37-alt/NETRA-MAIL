FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /opt/netra
COPY inspection/requirements.txt /opt/requirements.txt
RUN pip install --no-cache-dir -r /opt/requirements.txt
COPY backend/__init__.py backend/attachment_analyzer.py backend/image_analyzer.py backend/inspection_worker.py backend/controlled_fetch.py /opt/netra/backend/
COPY backend/pdf_inspection.py /opt/netra/backend/
USER 65532:65532
ENTRYPOINT ["python", "-m", "backend.inspection_worker"]
