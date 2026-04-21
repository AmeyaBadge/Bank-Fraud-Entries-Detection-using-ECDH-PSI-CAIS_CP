"""
celery_worker.py — DEPRECATED

The PSI Platform no longer uses Celery or Redis.
Batch PSI runs are executed using Python's threading.Thread directly
inside the Bank A FastAPI server (bank_a/tasks.py: run_psi_batch).

You do NOT need to run this file or install Redis.
"""
