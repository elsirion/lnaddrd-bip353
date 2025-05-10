# PostgreSQL development server management

# Default recipe to show available commands
default:
    @just --list

# Start the PostgreSQL development server
db-start:
    #!/usr/bin/env bash
    if [ -d "data/postgres" ]; then
        echo "PostgreSQL data directory already exists"
    else
        echo "Initializing PostgreSQL data directory..."
        mkdir -p data/postgres
        initdb -D data/postgres
        # Configure PostgreSQL to use local socket directory
        echo "unix_socket_directories = '/tmp'" >> data/postgres/postgresql.conf
        echo "listen_addresses = 'localhost'" >> data/postgres/postgresql.conf
    fi
    pg_ctl -D data/postgres start

# Stop the PostgreSQL development server
db-stop:
    pg_ctl -D data/postgres stop

# Show PostgreSQL server status
db-status:
    pg_ctl -D data/postgres status

# Create the development database
db-create:
    createdb -h localhost lnaddrd_dev

# Drop the development database
db-drop:
    dropdb -h localhost lnaddrd_dev

# Reset the development database (drop and recreate)
db-reset: db-drop db-create

# Connect to the development database
db-connect:
    psql -h localhost lnaddrd_dev

# Format the code
format:
    cargo fmt --all
