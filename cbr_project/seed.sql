INSERT OR IGNORE INTO users (name, email, password, admin)
VALUES ('Demo User', 'demo@example.com', 'demo', 0);

INSERT OR IGNORE INTO users (name, email, password, admin)
VALUES ('Admin User', 'admin@example.com', 'admin', 1);

INSERT OR IGNORE INTO restaurants (id, name, description)
VALUES (1, 'The SQL Diner', 'A deliberately vulnerable restaurant for security training.');

INSERT OR IGNORE INTO restaurants (id, name, description)
VALUES (2, 'Burger Barn', 'A quick-service spot for classic fast food favorites.');

INSERT OR IGNORE INTO menu_items (id, restaurant_id, name, description, price)
VALUES
    (1, 1, 'Classic Burger', 'A training-friendly diner classic.', 9.99),
    (2, 1, 'Veggie Bowl', 'Seasonal vegetables and rice.', 8.50),
    (3, 1, 'Chocolate Cake', 'A slice of chocolate cake.', 4.25),
    (4, 2, 'Burger', 'A juicy grilled burger with fresh toppings.', 12.50),
    (5, 2, 'Chicken Nuggets', 'Crispy golden chicken bites.', 7.75),
    (6, 2, 'Fries', 'Hot, salty fries straight from the fryer.', 5.50);

INSERT OR IGNORE INTO orders (id, user_id, address, status)
VALUES
    (1, 1, '12 Example Street', 'delivered'),
    (2, 2, '34 Demo Avenue', 'pending');

INSERT OR IGNORE INTO order_items (id, order_id, menu_item_id, quantity)
VALUES
    (1, 1, 1, 2),
    (2, 1, 3, 1),
    (3, 2, 4, 1);
