"""
celery_worker.py
Celery worker entry point. Import the Celery app from bank_a/tasks.py.

Run with:
    celery -A celery_worker worker --loglevel=info --concurrency=4
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from bank_a.tasks import celery_app  # noqa: F401 — imports the configured Celery instance

# Expose as 'app' for Celery CLI discovery
app = celery_app
