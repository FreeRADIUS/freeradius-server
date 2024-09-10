-- Create table for admin roles
CREATE TABLE admin_users (
    admin_id INT AUTO_INCREMENT PRIMARY KEY,
    admin_name VARCHAR(100),
    region_id INT,
    FOREIGN KEY (region_id) REFERENCES regions(region_id)
);

-- Insert example admin users
INSERT INTO admin_users (admin_name, region_id) VALUES 
('NairobiAdmin', 1),
('MalindiAdmin', 2),
('KisumuAdmin', 3);
