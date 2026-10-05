CREATE TABLE orders (
  id int PRIMARY KEY,
  amount numeric NOT NULL,
  CONSTRAINT orders_amount_positive CHECK (amount > 0)
);
CREATE TABLE order_items (
  id int PRIMARY KEY,
  order_id int NOT NULL,
  CONSTRAINT order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES orders(id)
);
INSERT INTO orders (id, amount) VALUES (1, 10), (2, 20);
INSERT INTO order_items (id, order_id) VALUES (1, 1), (2, 2);
