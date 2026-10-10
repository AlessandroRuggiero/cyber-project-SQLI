"""SQL queries used by the website.

The login query is intentionally vulnerable for the SQL injection exercise.
All other application queries use SQLite parameters.
"""


def enable_foreign_keys(conn):
    conn.execute("PRAGMA foreign_keys = ON")


def list_restaurants(conn):
    return conn.execute("SELECT * FROM restaurants").fetchall()

# vulnerable to boolean-based SQLi
def find_restaurant_vuln(conn, restaurant_id):
    query = "SELECT * FROM restaurants WHERE id = " + str(restaurant_id)
    return conn.execute(query).fetchone()


def list_menu_items(conn, restaurant_id):
    return conn.execute(
        "SELECT * FROM menu_items WHERE restaurant_id = ?",
        (restaurant_id,),
    ).fetchall()


def create_user(conn, name, email, password):
    return conn.execute(
        """
        INSERT INTO users (name, email, password, admin)
        VALUES (?, ?, ?, ?)
        """,
        (name, email, password, 0),
    )


def login_vulnerable(conn, email, password):
    query = (
        "SELECT * FROM users WHERE email ='"
        + email
        + "' AND password ='"
        + password
        + "'"
    )
    return conn.execute(query).fetchone()


def find_menu_item(conn, item_id):
    return conn.execute(
        "SELECT * FROM menu_items WHERE id = ?",
        (item_id,),
    ).fetchone()


def create_order(conn, user_id, address):
    return conn.execute(
        """
        INSERT INTO orders
            (user_id, address, status)
        VALUES
            (?, ?, ?)
        """,
        (user_id, address, "pending"),
    )


def find_order_item(conn, item_id):
    return conn.execute(
        """
        SELECT id
        FROM menu_items
        WHERE id = ?
        """,
        (item_id,),
    ).fetchone()


def create_order_item(conn, order_id, item_id, quantity):
    return conn.execute(
        """
        INSERT INTO order_items
            (order_id, menu_item_id, quantity)
        VALUES
            (?, ?, ?)
        """,
        (order_id, item_id, quantity),
    )


def find_order(conn, order_id, user_id):
    return conn.execute(
        """
        SELECT *
        FROM orders
        WHERE id = ?
        AND user_id = ?
        """,
        (order_id, user_id),
    ).fetchone()


def list_order_items(conn, order_id):
    return conn.execute(
        """
        SELECT
            menu_items.name,
            menu_items.price,
            order_items.quantity

        FROM order_items

        JOIN menu_items
        ON menu_items.id = order_items.menu_item_id

        WHERE order_items.order_id = ?
        """,
        (order_id,),
    ).fetchall()
