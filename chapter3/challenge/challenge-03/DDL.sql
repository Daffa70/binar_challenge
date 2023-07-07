CREATE DATABASE nokia_manufacture;

CREATE TABLE suppliers(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    address VARCHAR(255) NOT NULL
);

CREATE TABLE supplier_component(
    supplier_id BIGINT NOT NULL,
    components_id BIGINT NOT NULL
);

CREATE TABLE components(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(255) NOT NULL
);

CREATE TABLE components_product(
    components_id BIGINT NOT NULL,
    product_id BIGINT NOT NULL
);

CREATE TABLE products(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    qty INTEGER NOT NULL
);


-- STORED PROCEDURE
-- PRODUCT
CREATE OR REPLACE PROCEDURE update_qty (p_action TEXT, p_id INT, p_qty INT)
language plpgsql
as $$
BEGIN
    IF p_action = 'tambah' THEN
        UPDATE products 
        SET qty = qty + p_qty 
        WHERE id = p_id;
    ELSIF p_action = 'kurang' THEN
        UPDATE products 
        SET qty = qty - p_qty 
        WHERE id = p_id;
    ELSE 
        RAISE EXCEPTION 'Invalid action parameter: %', p_action;
    END IF;
commit;
end;$$;


CREATE OR REPLACE PROCEDURE delete_product(
    p_id integer
)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM products 
    WHERE id = p_id;
END;
$$;

-- SUPPLIER
CREATE OR REPLACE PROCEDURE insert_supplier (p_name TEXT, p_address TEXT)
language plpgsql
as $$
BEGIN
    INSERT INTO suppliers (name, address) VALUES (p_name, p_address);
commit;
end;$$;

CREATE OR REPLACE PROCEDURE delete_supplier (p_id integer)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM suppliers
    WHERE id = p_id;
END;
$$;

-- COMPONENTS
CREATE OR REPLACE PROCEDURE insert_component (p_name TEXT, p_description TEXT)
language plpgsql
as $$
BEGIN
    INSERT INTO components (name, description) VALUES (p_name, p_description);
commit;
end;$$;

CREATE OR REPLACE PROCEDURE delete_component (p_id integer)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM components 
    WHERE id = p_id;
END;
$$;

-- SUPPLIER COMPONENTS
CREATE OR REPLACE PROCEDURE insert_supplier_compenent (p_supplier_id INTEGER, p_components_id INTEGER)
language plpgsql
as $$
BEGIN
    INSERT INTO supplier_component (supplier_id, components_id) VALUES (p_supplier_id, p_components_id);
commit;
end;$$;

CREATE OR REPLACE PROCEDURE delete_supplier_component (p_supplier_id INTEGER, p_components_id INTEGER)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM supplier_component 
    WHERE supplier_id = p_supplier_id AND components_id = p_components_id;
END;
$$;

-- components_product
CREATE OR REPLACE PROCEDURE insert_components_product (p_components_id INT, p_product_id INT)
language plpgsql
as $$
BEGIN
    INSERT INTO components_product (components_id, product_id) VALUES (p_components_id, p_product_id);
commit;
end;$$;

CREATE OR REPLACE PROCEDURE delete_components_product (p_components_id INT, p_product_id INT)
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM components_product
    WHERE p_components_id = components_id AND p_product_id = product_id;
END;
$$;