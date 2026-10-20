# AI disclosure
## Per group member
### Martin Erikers (erikers@kth.se)
No AI use

### etc
## Repo map
(Base initially generated via `$ tree cyber-project-SQLI/`)
```
cyber-project-SQLI/
├── AI-DISCLOSURE.md                            (erikers@kth.se, no AI)
├── cbr_project
│   ├── boolean
│   │   ├── boolean_extractor.py
│   │   ├── db_dumper.py
│   │   ├── demo_boolean.mp4
│   │   ├── exploit.sh
│   ├── database.db
│   ├── init_db.py
│   ├── main.py
│   ├── proxy
│   │   ├── app.py
│   │   ├── config.py
│   │   ├── detector.py
│   │   ├── detectors
│   │   │   ├── example_metadata.py
│   │   │   ├── example_obvious_injection.py
│   │   │   ├── example_sql_tokens.py
│   │   │   ├── example_time_based.py
│   │   │   ├── __init__.py
│   │   │   ├── regex_rules.py                  (erikers@kth.se, no AI)
│   │   │   ├── tokenizer.py                    (erikers@kth.se, no AI)
│   │   │   └── util.py                         (erikers@kth.se, no AI)
│   │   ├── echo_backend.py
│   │   ├── http
│   │   │   ├── attacks.http
│   │   │   ├── benign.http
│   │   │   ├── boolean.http
│   │   │   ├── mixed.http
│   │   │   └── run_http.py
│   │   ├── README.md
│   │   ├── reputation.py
│   │   └── schema_constraint.py                (erikers@kth.se, no AI)
│   ├── queries.py
│   ├── schema.sql
│   ├── seed.sql
│   └── website
│       ├── static
│       │   ├── images
│       │   │   ├── bowl.jpg
│       │   │   ├── burger-barn.jpg
│       │   │   ├── burger.jpg
│       │   │   ├── chicken-nuggets.jpg
│       │   │   ├── chocolate-cake.jpg
│       │   │   ├── fries.jpg
│       │   │   ├── hero.jpg
│       │   │   └── restaurant.jpg
│       │   └── style.css
│       └── templates
│           ├── base.html
│           ├── cart.html
│           ├── edit.html
│           ├── indexadmin.html
│           ├── index.html
│           ├── login.html
│           ├── order.html
│           ├── order_lookup.html
│           ├── register.html
│           └── restaurant.html
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.proxy
├── pyproject.toml
├── pytest.ini
├── README.md
├── README.old.md
├── requirements-dev.txt
├── requirements-libinjection.txt
├── requirements.txt
└── tests
    └── test_proxy.py
```