FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p uploads templates

EXPOSE 5050

CMD ["waitress-serve", "--host=0.0.0.0", "--port=5050", "app:app"]