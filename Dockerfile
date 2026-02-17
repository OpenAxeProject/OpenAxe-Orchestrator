FROM python:3.9-slim

RUN pip install flask requests pytz pynostr

WORKDIR /app
COPY . .

CMD ["python", "app.py"]
