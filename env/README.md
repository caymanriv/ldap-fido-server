# Environment Configuration

This directory contains environment configuration files for different services and environments.

## Structure

```
env/
├── client/               # Client-side environment variables
│   ├── development/     # Development environment
│   ├── staging/        # Staging environment
│   ├── production/     # Production environment
│   └── testing/        # Testing environment
└── server/             # Server-side environment variables
    ├── development/
    ├── staging/
    ├── production/
    └── testing/
```

## Usage

1. Create the environment files for the environment you want to run:
   ```bash
   # Server (Docker Compose via server/Makefile)
   cp config/env/server.env.example env/server/development/.env

   # Client (optional; only needed if you run Vite directly)
   cp config/env/client.env.example env/client/development/.env
   ```

2. The `.gitignore` is configured to ignore these local `.env` files.

3. When using Docker Compose via `server/Makefile`, the compose commands use the env files from this `env/` directory directly (via `--env-file`). No need to copy files into `server/.env`.

## Adding New Variables

1. Add the variable to all relevant environment files
2. Update the documentation in the appropriate service's README
3. Ensure proper default values are set for development

## Security Note

Never commit sensitive information to version control. The `.env` files in version control should only contain non-sensitive default values for development.
