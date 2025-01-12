PGDMP             
            {            nokia_manufacture    15.2    15.2 '    "           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            #           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            $           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            %           1262    24800    nokia_manufacture    DATABASE     �   CREATE DATABASE nokia_manufacture WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
 !   DROP DATABASE nokia_manufacture;
                postgres    false            �            1255    24900    delete_component(integer) 	   PROCEDURE     �   CREATE PROCEDURE public.delete_component(IN p_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM components 
    WHERE id = p_id;
END;
$$;
 9   DROP PROCEDURE public.delete_component(IN p_id integer);
       public          postgres    false            �            1255    24904 +   delete_components_product(integer, integer) 	   PROCEDURE       CREATE PROCEDURE public.delete_components_product(IN p_components_id integer, IN p_product_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM components_product
    WHERE p_components_id = components_id AND p_product_id = product_id;
END;
$$;
 f   DROP PROCEDURE public.delete_components_product(IN p_components_id integer, IN p_product_id integer);
       public          postgres    false            �            1255    24896    delete_product(integer) 	   PROCEDURE     �   CREATE PROCEDURE public.delete_product(IN p_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM products 
    WHERE id = p_id;
END;
$$;
 7   DROP PROCEDURE public.delete_product(IN p_id integer);
       public          postgres    false            �            1255    24898    delete_supplier(integer) 	   PROCEDURE     �   CREATE PROCEDURE public.delete_supplier(IN p_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM suppliers
    WHERE id = p_id;
END;
$$;
 8   DROP PROCEDURE public.delete_supplier(IN p_id integer);
       public          postgres    false            �            1255    24902 +   delete_supplier_component(integer, integer) 	   PROCEDURE       CREATE PROCEDURE public.delete_supplier_component(IN p_supplier_id integer, IN p_components_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM supplier_component 
    WHERE supplier_id = p_supplier_id AND components_id = p_components_id;
END;
$$;
 g   DROP PROCEDURE public.delete_supplier_component(IN p_supplier_id integer, IN p_components_id integer);
       public          postgres    false            �            1255    24899    insert_component(text, text) 	   PROCEDURE     �   CREATE PROCEDURE public.insert_component(IN p_name text, IN p_description text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO components (name, description) VALUES (p_name, p_description);
commit;
end;$$;
 O   DROP PROCEDURE public.insert_component(IN p_name text, IN p_description text);
       public          postgres    false            �            1255    24903 +   insert_components_product(integer, integer) 	   PROCEDURE       CREATE PROCEDURE public.insert_components_product(IN p_components_id integer, IN p_product_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO components_product (components_id, product_id) VALUES (p_components_id, p_product_id);
commit;
end;$$;
 f   DROP PROCEDURE public.insert_components_product(IN p_components_id integer, IN p_product_id integer);
       public          postgres    false            �            1255    24897    insert_supplier(text, text) 	   PROCEDURE     �   CREATE PROCEDURE public.insert_supplier(IN p_name text, IN p_address text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO suppliers (name, address) VALUES (p_name, p_address);
commit;
end;$$;
 J   DROP PROCEDURE public.insert_supplier(IN p_name text, IN p_address text);
       public          postgres    false            �            1255    24901 +   insert_supplier_compenent(integer, integer) 	   PROCEDURE       CREATE PROCEDURE public.insert_supplier_compenent(IN p_supplier_id integer, IN p_components_id integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO supplier_component (supplier_id, components_id) VALUES (p_supplier_id, p_components_id);
commit;
end;$$;
 g   DROP PROCEDURE public.insert_supplier_compenent(IN p_supplier_id integer, IN p_components_id integer);
       public          postgres    false            �            1255    24895 "   update_qty(text, integer, integer) 	   PROCEDURE     �  CREATE PROCEDURE public.update_qty(IN p_action text, IN p_id integer, IN p_qty integer)
    LANGUAGE plpgsql
    AS $$
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
 W   DROP PROCEDURE public.update_qty(IN p_action text, IN p_id integer, IN p_qty integer);
       public          postgres    false            �            1259    24877 
   components    TABLE     �   CREATE TABLE public.components (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255) NOT NULL
);
    DROP TABLE public.components;
       public         heap    postgres    false            �            1259    24876    components_id_seq    SEQUENCE     z   CREATE SEQUENCE public.components_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.components_id_seq;
       public          postgres    false    218            &           0    0    components_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.components_id_seq OWNED BY public.components.id;
          public          postgres    false    217            �            1259    24885    components_product    TABLE     n   CREATE TABLE public.components_product (
    components_id bigint NOT NULL,
    product_id bigint NOT NULL
);
 &   DROP TABLE public.components_product;
       public         heap    postgres    false            �            1259    24889    products    TABLE     }   CREATE TABLE public.products (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    qty integer NOT NULL
);
    DROP TABLE public.products;
       public         heap    postgres    false            �            1259    24888    products_id_seq    SEQUENCE     x   CREATE SEQUENCE public.products_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.products_id_seq;
       public          postgres    false    221            '           0    0    products_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.products_id_seq OWNED BY public.products.id;
          public          postgres    false    220            �            1259    24873    supplier_component    TABLE     o   CREATE TABLE public.supplier_component (
    supplier_id bigint NOT NULL,
    components_id bigint NOT NULL
);
 &   DROP TABLE public.supplier_component;
       public         heap    postgres    false            �            1259    24865 	   suppliers    TABLE     �   CREATE TABLE public.suppliers (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    address character varying(255) NOT NULL
);
    DROP TABLE public.suppliers;
       public         heap    postgres    false            �            1259    24864    suppliers_id_seq    SEQUENCE     y   CREATE SEQUENCE public.suppliers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.suppliers_id_seq;
       public          postgres    false    215            (           0    0    suppliers_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.suppliers_id_seq OWNED BY public.suppliers.id;
          public          postgres    false    214            �           2604    24880    components id    DEFAULT     n   ALTER TABLE ONLY public.components ALTER COLUMN id SET DEFAULT nextval('public.components_id_seq'::regclass);
 <   ALTER TABLE public.components ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    218    217    218            �           2604    24892    products id    DEFAULT     j   ALTER TABLE ONLY public.products ALTER COLUMN id SET DEFAULT nextval('public.products_id_seq'::regclass);
 :   ALTER TABLE public.products ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    220    221    221            �           2604    24868    suppliers id    DEFAULT     l   ALTER TABLE ONLY public.suppliers ALTER COLUMN id SET DEFAULT nextval('public.suppliers_id_seq'::regclass);
 ;   ALTER TABLE public.suppliers ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215                      0    24877 
   components 
   TABLE DATA           ;   COPY public.components (id, name, description) FROM stdin;
    public          postgres    false    218   0                 0    24885    components_product 
   TABLE DATA           G   COPY public.components_product (components_id, product_id) FROM stdin;
    public          postgres    false    219   �0                 0    24889    products 
   TABLE DATA           1   COPY public.products (id, name, qty) FROM stdin;
    public          postgres    false    221   1                 0    24873    supplier_component 
   TABLE DATA           H   COPY public.supplier_component (supplier_id, components_id) FROM stdin;
    public          postgres    false    216   `1                 0    24865 	   suppliers 
   TABLE DATA           6   COPY public.suppliers (id, name, address) FROM stdin;
    public          postgres    false    215   �1       )           0    0    components_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.components_id_seq', 11, true);
          public          postgres    false    217            *           0    0    products_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.products_id_seq', 3, true);
          public          postgres    false    220            +           0    0    suppliers_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.suppliers_id_seq', 3, true);
          public          postgres    false    214            �           2606    24884    components components_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.components DROP CONSTRAINT components_pkey;
       public            postgres    false    218            �           2606    24894    products products_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.products DROP CONSTRAINT products_pkey;
       public            postgres    false    221            �           2606    24872    suppliers suppliers_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.suppliers
    ADD CONSTRAINT suppliers_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.suppliers DROP CONSTRAINT suppliers_pkey;
       public            postgres    false    215               �   x�m�1��@���>�O�X(!�@"�hGt4��B�M��X��A(����*�P�8n[Q�8D�5=�G�q7���PICKwc�G�E��H�+2�F�\��q�oO��hY�l�9�́�O����nJ�ߐن�R�̋r�T�q>�q�f�aO�-M`ec���R�Y��Y]�Ӿ�?���z?����T�G�x�i�         2   x�ȹ 1�X,�3��r��q ��j��k-\��6�!����         5   x�3�����tT0604�44�2��C�rRKL9-��b&&@5F�\1z\\\ h��         /   x�ƹ  ���W���B�u�`GrX��PFa�nzpyw��k�>�9         J   x�3�t�S���N�Q(�LIU�H,J)O,J��L�O,���2�у�+�&f�*x%V&r�&�$�s��qqq TP}     