-- Create the "ecommerce" database to store all related tables and data
CREATE DATABASE ecommerce;
-- Switch to using the newly created "ecommerce" database
USE ecommerce;

-------------------------------------------------------------
-- Create Users Table
-------------------------------------------------------------
-- This table stores user information including login credentials and account creation date.
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique user ID; auto-incremented integer; primary key
    username VARCHAR(50) UNIQUE NOT NULL,              -- Username of the user; must be unique and not null
    email VARCHAR(100) UNIQUE NOT NULL,                -- User's email address; must be unique and not null
    password VARCHAR(255) NOT NULL,                    -- Hashed password; not null
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP     -- Timestamp of account creation; defaults to current time
);

-- Query to check contents of the users table (for debugging or verification)
select * from users;

-------------------------------------------------------------
-- Create Products Table
-------------------------------------------------------------
-- This table contains product details including price, quantity, quality, discount, and seller status.
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique product ID; auto-incremented; primary key
    name VARCHAR(100) NOT NULL,                        -- Name of the product; not null
    description TEXT,                                  -- Detailed description of the product
    price DECIMAL(10,2) NOT NULL,                      -- Price of the product with up to 10 digits and 2 decimal places; not null
    quantity INT NOT NULL,                             -- Available quantity in stock; not null
    quality VARCHAR(50),                               -- Quality description (e.g., "Premium", "High")
    discount DECIMAL(5,2) DEFAULT 0.00,                -- Discount percentage, if any; defaults to 0.00
    best_seller BOOLEAN DEFAULT FALSE,                 -- Boolean flag indicating if the product is a best seller; defaults to FALSE
    image VARCHAR(255),                                -- Path or URL to the product image
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP     -- Timestamp when the product was added; defaults to current time
);

-- Query to verify the products table content
select * from products;

-------------------------------------------------------------
-- Insert Sample Product Data
-------------------------------------------------------------
-- Insert sample data for products covering a variety of electronics and accessories.
INSERT INTO products (name, description, price, quantity, quality, discount, best_seller, image) VALUES
('Laptop', 'A high-performance laptop with the latest processor and 16GB RAM.', 1000.00, 10, 'Premium', 10.00, TRUE, 'static/images/laptop.png'),
('Smartphone', 'A latest-gen smartphone with AI camera and 5G connectivity.', 700.00, 20, 'High', 5.00, FALSE, 'static/images/smartphone.jpg'),
('Headphones', 'Noise-cancelling headphones with immersive sound experience.', 150.00, 50, 'Premium', 15.00, TRUE, 'static/images/headphones.jpg'),
('Smartwatch', 'A feature-rich smartwatch with health tracking and notifications.', 250.00, 30, 'High', 8.00, FALSE, 'static/images/smartwatch.jpg'),
('Tablet', 'A powerful tablet with 10-inch display and stylus support.', 500.00, 15, 'Premium', 12.00, FALSE, 'static/images/tablet.jpg'),
('Gaming Console', 'Next-gen gaming console with ultra HD graphics.', 600.00, 10, 'High', 7.00, TRUE, 'static/images/console.jpg'),
('Wireless Earbuds', 'Compact earbuds with noise cancellation and long battery life.', 120.00, 40, 'Premium', 10.00, TRUE, 'static/images/earbuds.jpg'),
('Camera', 'Professional-grade DSLR camera with 4K video recording.', 1200.00, 5, 'Professional', 5.00, FALSE, 'static/images/camera.jpg'),
('Monitor', '4K Ultra HD monitor with high refresh rate for gaming.', 300.00, 25, 'High', 10.00, TRUE, 'static/images/monitor.jpg'),
('Keyboard', 'Mechanical keyboard with RGB lighting and fast response keys.', 80.00, 100, 'Premium', 5.00, FALSE, 'static/images/keyboard.jpg');

-------------------------------------------------------------
-- Create Cart Table
-------------------------------------------------------------
-- This table stores products that users have added to their cart before proceeding to checkout.
CREATE TABLE cart (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique cart item ID; primary key
    user_id INT,                                       -- Foreign key: ID of the user who added the item to the cart
    product_id INT,                                    -- Foreign key: ID of the product added to the cart
    quantity INT NOT NULL,                             -- Quantity of the product added; not null
    FOREIGN KEY (user_id) REFERENCES users(id),         -- Enforces referential integrity with the users table
    FOREIGN KEY (product_id) REFERENCES products(id)    -- Enforces referential integrity with the products table
);

-------------------------------------------------------------
-- Create Orders Table
-------------------------------------------------------------
-- This table manages order transactions including address, status, and payment method.
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique order ID; primary key
    user_id INT,                                       -- Foreign key: ID of the user who placed the order
    product_id INT,                                    -- Foreign key: ID of the product ordered
    quantity INT NOT NULL,                             -- Quantity of product ordered; not null
    total_price DECIMAL(10,2) NOT NULL,                -- Total price for the order; not null
    address TEXT NOT NULL,                             -- Shipping address; not null
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,    -- Order placement date; defaults to current time
    delivery_date TIMESTAMP,                           -- Expected delivery date (can be NULL initially)
    status ENUM('Processing', 'Shipped', 'Out for Delivery', 'Delivered', 'Returned', 'Cancelled') DEFAULT 'Processing',  -- Order status with defined values; defaults to 'Processing'
    payment_mode VARCHAR(50),                          -- Mode of payment (e.g., "Razorpay", "Credit Card")
    payment_status ENUM('Pending', 'Completed', 'Failed', 'Refunded') DEFAULT 'Pending', -- Payment status with defined values; defaults to 'Pending'
    tracking_id VARCHAR(50) UNIQUE,                    -- Unique tracking ID for shipments
    shipped_date TIMESTAMP NULL DEFAULT NULL,          -- Date when the order was shipped; nullable
    delivered_date TIMESTAMP NULL DEFAULT NULL,        -- Date when the order was delivered; nullable
    return_request BOOLEAN DEFAULT FALSE,              -- Flag indicating if a return request has been made; defaults to FALSE
    return_reason TEXT DEFAULT NULL,                   -- Reason for return (if any); nullable
    order_notes TEXT DEFAULT NULL,                     -- Additional notes regarding the order; nullable
    coupon_code VARCHAR(50) DEFAULT NULL,              -- Coupon code applied (if any); nullable
    discount_applied DECIMAL(10,2) DEFAULT 0.00,         -- Discount amount applied to the order; defaults to 0.00
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,  -- Timestamp for the last update; auto-updated on modifications
    FOREIGN KEY (user_id) REFERENCES users(id),         -- Foreign key: References the users table for user ID
    FOREIGN KEY (product_id) REFERENCES products(id)    -- Foreign key: References the products table for product ID
);

-- Query to check the contents of the orders table
select * from orders;



-------------------------------------------------------------
-- Create Wishlist Table
-------------------------------------------------------------
-- This table keeps track of products that users mark as favorites to purchase later.
CREATE TABLE wishlist (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique wishlist ID; primary key
    user_id INT,                                       -- Foreign key: ID of the user who favorited the product
    product_id INT,                                    -- Foreign key: ID of the favorited product
    FOREIGN KEY (user_id) REFERENCES users(id),         -- Enforces referential integrity with the users table
    FOREIGN KEY (product_id) REFERENCES products(id)    -- Enforces referential integrity with the products table
);

-------------------------------------------------------------
-- Create Reviews Table
-------------------------------------------------------------
-- This table stores user ratings and comments for products.
CREATE TABLE reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,                -- Unique review ID; primary key
    user_id INT,                                       -- Foreign key: ID of the user who wrote the review
    product_id INT,                                    -- Foreign key: ID of the product being reviewed
    rating DECIMAL(2,1) CHECK (rating BETWEEN 1 AND 5), -- Rating given by the user; must be between 1 and 5
    comment TEXT,                                      -- The review text or comment
    FOREIGN KEY (user_id) REFERENCES users(id),         -- Enforces referential integrity with the users table
    FOREIGN KEY (product_id) REFERENCES products(id)    -- Enforces referential integrity with the products table
);
