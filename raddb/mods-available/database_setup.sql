-- Create regions table
CREATE TABLE regions (
    region_id INT AUTO_INCREMENT PRIMARY KEY,
    region_name VARCHAR(100) NOT NULL
);

-- Create table to map users to regions
CREATE TABLE region_users (
    user_id INT,
    region_id INT,
    PRIMARY KEY(user_id, region_id),
    FOREIGN KEY(user_id) REFERENCES radcheck(id),
    FOREIGN KEY(region_id) REFERENCES regions(region_id)
);

-- Insert example regions
INSERT INTO regions (region_name) VALUES ('Nairobi'), ('Migori'), ('Kisumu'), ('Malindi');

-- Assign users to regions (this needs to be updated when users are added)
INSERT INTO region_users (user_id, region_id) VALUES 
(1, 1), -- Fredrick Arara -> Nairobi Region
(2, 2), -- Maureen Makumi -> Malidi Region
(3, 3); -- Robert Idewa -> Kisumu Region
