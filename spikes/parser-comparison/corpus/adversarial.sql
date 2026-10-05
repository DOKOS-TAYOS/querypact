-- Adversarial / reproducible SQL corpus for parser spike (P01-P11).
-- Literals use .invalid TLD canaries; no real credentials.

-- P01
SELECT id, email FROM users WHERE active = true;

-- P02
WITH active_users AS (
  SELECT id FROM users WHERE active = true
)
SELECT o.id FROM orders o
JOIN active_users au ON au.id = o.user_id;

-- P03
SELECT id FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 10);

-- P04
INSERT INTO users (id, email) VALUES (1, 'canary@example.invalid');

-- P05
UPDATE users SET email = 'x@example.invalid' WHERE id = 1;

-- P06
DELETE FROM users WHERE id = 1;

-- P07
CREATE TABLE t_spike (id int);
ALTER TABLE t_spike ADD COLUMN name text;
DROP TABLE t_spike;

-- P08
SELECT 1; SELECT 2;

-- P09
SELEC id FROM users;

-- P10 variants
SELECT   id  FROM   users;
select id from users;

-- P11 variants (literals differ; fingerprint over normalized form must match)
SELECT id FROM users WHERE id = 42;
select   id from users where id = 99;
