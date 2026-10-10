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
python3 cbr_project/init_db.py
flask --app cbr_project.main:main run
```

The backend is available at http://127.0.0.1:5000. The version with input
parameterization can be found in `cbr_project/injection`.
The version with input parameterization can be found in the folder called "injection".
