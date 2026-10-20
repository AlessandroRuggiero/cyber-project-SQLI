## Running with Docker

Docker Compose creates the SQLite database, applies the schema, loads demo data,
installs the Python dependencies, and starts the vulnerable website behind the
SQL injection filtering proxy:

```bash
docker compose up --build
```

Open http://127.0.0.1:8080. Stop the stack with:

```bash
docker compose down
```

The database is stored in the `database-data` Docker volume. To recreate it
from scratch, remove that volume with `docker compose down -v`.

Demo accounts:

- `demo@example.com` / `demo`
- `admin@example.com` / `admin`

## Running the backend directly

The backend can also be run without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m cbr_project.init_db
flask --app cbr_project.main:main run
```

The backend is available at http://127.0.0.1:5000. The application is a single
shared website with one deliberately vulnerable login query for the SQLi
exercise; the remaining database queries use parameters.

The training vulnerability is scoped to `POST /login`. Do not add new
string-built SQL queries elsewhere: keeping the vulnerable surface small makes
the exercise easier to understand and the application easier to maintain.

## Project layout

The Flask backend is in `cbr_project/main.py`, and its frontend files are
grouped under `cbr_project/website`:

- `cbr_project/website/templates` and `cbr_project/website/static` contain the
  templates, stylesheet, and images.

The database schema, seed data, and SQLite file remain directly under
`cbr_project`. The proxy code remains under `cbr_project/proxy`.
