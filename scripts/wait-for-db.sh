#!/bin/sh
set -e

HOST=${DB_HOST:-db}
PORT=${DB_PORT:-5432}

echo "Waiting for database at ${HOST}:${PORT}..."
retries=30
count=0
until nc -z "$HOST" "$PORT"; do
  count=$((count+1))
  if [ "$count" -ge "$retries" ]; then
    echo "Database not reachable after ${retries} attempts, exiting."
    exit 1
  fi
  sleep 2
done

echo "Database reachable, starting app"
exec "$@"
