INSERT INTO suppliers (name, address) VALUES
    ('PT. Hardware Maju Jaya', 'Surabaya'),
    ('CV. Lokal Pride Hardware', 'Sidoarjo');

INSERT INTO components (name, description) VALUES
    ('Processor', 'Central Processing Unit'),
    ('Memory', 'Random Access Memory'),
    ('Storage', 'Solid State Drive'),
    ('Display AMOLED', 'Screen Display'),
    ('Display OLED', 'Screen Display'),
    ('Display IPS', 'Screen Display'),
    ('Camera 108MP', 'Camera Module'),
    ('Camera 20MP', 'Camera Module'),
    ('Camera 50MP', 'Camera Module'),
    ('Battery', 'Power Source');

INSERT INTO products (name, qty) VALUES
    ('NOKIA 4410', 20),
    ('NOKIA 3010', 15),
    ('NOKIA Tablet 4A', 8);

INSERT INTO supplier_component (supplier_id, components_id) VALUES
    (1, 1),
    (1, 2),
    (1, 3),
    (2, 4),
    (2, 5),
    (1, 6),
    (2, 7),
    (1, 8),
    (1, 9),
    (2, 10);

INSERT INTO components_product (components_id, product_id) VALUES
    (1, 1),
    (2, 1),
    (3, 1),
    (4, 1),
    (7, 1),
    (1, 2),
    (2, 2),
    (3, 2),
    (5, 2),
    (8, 2),
    (1, 3),
    (2, 3),
    (3, 3),
    (6, 3),
    (9, 3);

UPDATE suppliers
SET address = 'Malang'
WHERE id = 1;

DELETE FROM components_product
WHERE components_id = 1 AND product_id = 1;

--SELECT QUERY
select 
    products.name as Nama_Product,
    products.qty,
    components.name as Nama_Komponen,
    components.description as Deskripsi_Komponen
from 
    products
    join components_product on components_product.product_id = products.id
    join components on components.id = components_product.components_id
order by 
    products.id;


select 
    suppliers.name as Nama_Supplier,
    suppliers.address,
    components.name as Nama_Komponen,
    components.description as Deskripsi_Komponen
from 
    suppliers
    join supplier_component on supplier_component.supplier_id = suppliers.id
    join components on components.id = supplier_component.components_id
order by 
    suppliers.id;



