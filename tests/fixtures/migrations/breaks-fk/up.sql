ALTER TABLE order_items DROP CONSTRAINT order_items_order_id_fkey;
INSERT INTO order_items (id, order_id) VALUES (999, 999);
