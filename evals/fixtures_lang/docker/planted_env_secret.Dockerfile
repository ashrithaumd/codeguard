# Planted: a real-looking session secret baked into the image with ENV.
# Decided by its shape alone; this line must never reach the model.
FROM python:3.12.7-slim

ENV APP_ENV=production     PORT=8000
ENV SESSION_SECRET=woQZcU1qvzuwqO8lkzWDaYKGsuCMYkmwstgWfRdf

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN useradd --create-home --uid 10001 web
USER web
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
