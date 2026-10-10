INSERT OR IGNORE INTO users (name, email, password, admin)
VALUES ('Demo User', 'demo@example.com', 'demo', 0);

INSERT OR IGNORE INTO users (name, email, password, admin)
VALUES ('Admin User', 'admin@example.com', 'admin', 1);

INSERT OR IGNORE INTO restaurants (id, name, description)
VALUES (1, 'The SQL Diner', 'A deliberately vulnerable restaurant for security training.');

INSERT OR IGNORE INTO menu_items (id, restaurant_id, name, description, price)
VALUES
    (1, 1, 'Classic Burger', 'A training-friendly diner classic.', 9.99),
    (2, 1, 'Veggie Bowl', 'Seasonal vegetables and rice.', 8.50),
    (3, 1, 'Chocolate Cake', 'A slice of chocolate cake.', 4.25);
