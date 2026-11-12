#!/usr/bin/env bash
# One-time local database setup for development (Ubuntu).
#
#   bash scripts/setup_db.sh        (run from the project root, as a user with sudo)
#
# - installs MySQL if missing, with a low-memory configuration
# - creates two databases: log_analyzer (the app) and log_analyzer_test (tests only)
# - creates the app user with a random password and writes it to .env
#   (.env is in .gitignore - the password never reaches GitHub, and is never printed)
# - creates the tables from schema.sql in the app database
#
# Safe to run again: reuses the password already in .env.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"
DB_NAME="log_analyzer"
TEST_DB_NAME="log_analyzer_test"
DB_USER="log_analyzer"

# 1. Install MySQL
if ! command -v mysqld > /dev/null; then
    echo "Installing MySQL..."
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mysql-server > /dev/null
fi

# 2. Low-memory settings: the development VM has only 3 GB of RAM
LOW_MEMORY_CNF=/etc/mysql/mysql.conf.d/zz-low-memory.cnf
if [ ! -f "$LOW_MEMORY_CNF" ]; then
    echo "Applying low-memory MySQL settings..."
    sudo tee "$LOW_MEMORY_CNF" > /dev/null <<'CNF'
[mysqld]
performance_schema      = OFF
innodb_buffer_pool_size = 64M
max_connections         = 20
CNF
    sudo systemctl restart mysql
fi
sudo systemctl enable --now mysql > /dev/null 2>&1

# 3. Password: reuse the one in .env, or create a new random one
if [ -f "$ENV_FILE" ] && grep -q '^DB_PASSWORD=' "$ENV_FILE"; then
    DB_PASSWORD="$(grep '^DB_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
else
    DB_PASSWORD="$(openssl rand -hex 24)"
fi

# 4. Databases, user, permissions (as the MySQL root user, via sudo)
sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME}      CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS ${TEST_DB_NAME} CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.*      TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${TEST_DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# 5. Write .env (readable only by its owner)
cat > "$ENV_FILE" <<ENV
# Local development settings - never commit this file
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DB_NAME=${DB_NAME}
DB_TEST_NAME=${TEST_DB_NAME}
ENV
chmod 600 "$ENV_FILE"

# 6. Tables
MYSQL_PWD="$DB_PASSWORD" mysql -h 127.0.0.1 -u "$DB_USER" "$DB_NAME" < "$PROJECT_DIR/schema.sql"

echo "Done. Databases: $DB_NAME, $TEST_DB_NAME. Settings written to .env"
