#!/bin/sh
# Wait for Postgres to be ready, then initialize app_variables from .env
set -e

# Load env vars from mounted file if present
if [ -f /app/server/.env ]; then
  export $(grep -v '^#' /app/server/.env | xargs)
fi

# Fail fast if required DB variables are missing
if [ -z "$DB_HOST" ] || [ -z "$DB_PORT" ] || [ -z "$DB_USER" ]; then
  echo "Error: DB_HOST, DB_PORT, and DB_USER must be set. Check /app/server/.env."
  exit 1
fi

until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER"; do
  echo "Waiting for postgres..."
  sleep 2
done

# Run the Node.js init script
node /app/scripts/init-app-variables.js
