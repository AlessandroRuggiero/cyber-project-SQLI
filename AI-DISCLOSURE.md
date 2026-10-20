# AI disclosure
## Martin Erikers (erikers@kth.se)
No AI use.

## Alessandro Ruggiero
The echo backend was ai generated, the reason is just to quickly get a look at what the proxy is doing in a convenient way.
The prompt was "I need a simple http server that will logs its request to test my proxy, just one quick file with flask, here is the file extracts the info form the request, i want all those logged " + file containing extract_inputs

## Siri, left group
Majority AI-generated, prompts unknown, all/most files have changed since
- [cbr_project/main.py](cbr_project/main.py)
- [cbr_project/schema.sql](cbr_project/schema.sql)
- [cbr_project/database.db](cbr_project/database.db)

- [cbr_project/static/style.css](cbr_project/static/style.css)
- [cbr_project/templates/base.html](cbr_project/templates/base.html)
- [cbr_project/templates/cart.html](cbr_project/templates/cart.html)
- [cbr_project/templates/index.html](cbr_project/templates/index.html)
- [cbr_project/templates/login.html](cbr_project/templates/login.html)
- [cbr_project/templates/order.html](cbr_project/templates/order.html)
- [cbr_project/templates/register.html](cbr_project/templates/register.html)
- [cbr_project/templates/restaurant.html](cbr_project/templates/restaurant.html)

- [cbr_project/requirements.txt](cbr_project/requirements.txt)

The following are deleted in the current version of the repo:
- [cbr_project/injection/database.db](cbr_project/injection/database.db)
- [cbr_project/injection/schema.sql](cbr_project/injection/schema.sql)
- [cbr_project/injection/static/style.css](cbr_project/injection/static/style.css)
- [cbr_project/injection/templates/base.html](cbr_project/injection/templates/base.html)
- [cbr_project/injection/templates/cart.html](cbr_project/injection/templates/cart.html)
- [cbr_project/injection/templates/index.html](cbr_project/injection/templates/index.html)
- [cbr_project/injection/templates/login.html](cbr_project/injection/templates/login.html)
- [cbr_project/injection/templates/order.html](cbr_project/injection/templates/order.html)
- [cbr_project/injection/templates/register.html](cbr_project/injection/templates/register.html)
- [cbr_project/injection/templates/restaurant.html](cbr_project/injection/templates/restaurant.html)

- [cbr_project/README.md](cbr_project/README.md) (old, no relation to current readme)

## Gioele Bucci
I've used AI to improve the UI of the website (making the model iterate on the work of Siri). Prompt was: "Can you give the website a facelift? Only improve it UI-wise and do not fix the intentionally vulnerable SQL queries".
Also used AI to setup containerization for the project to allow for easier deployment and project reproducibility. Prompt was: "Can you conteinerize our project? Create two separate containers for the backend and proxy and a single Docker compose file to bring the project up or down".
