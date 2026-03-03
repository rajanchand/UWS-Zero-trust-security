"""Gunicorn config for production. Run: gunicorn main:app -c gunicorn_conf.py"""

import multiprocessing

bind = "0.0.0.0:8000"

workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"

timeout = 120
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = "info"

# Security
limit_request_line = 8190
limit_request_fields = 100
