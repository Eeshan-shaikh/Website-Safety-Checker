import sqlite3

# Connect to database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Categories to insert
categories = [
    ('Shopping', 'E-commerce and retail websites', 1),
    ('Social Media', 'Social networking platforms', 2),
    ('Banking', 'Financial institutions and banking services', 4),
    ('News', 'News sites and information portals', 1),
    ('Entertainment', 'Streaming services, games, and media', 1),
    ('Education', 'Educational resources and institutions', 0),
    ('Technology', 'Tech companies and services', 1),
    ('Government', 'Government websites and services', 0),
    ('Health', 'Healthcare and medical information', 2),
    ('Travel', 'Travel booking and information', 2),
    ('Business', 'Corporate and business websites', 1),
    ('Adult Content', 'Adult and mature content', 5),
    ('Gambling', 'Betting and gambling sites', 4),
    ('Cryptocurrency', 'Cryptocurrency exchanges and services', 3),
    ('Forums', 'Discussion boards and forums', 2),
    ('Gaming', 'Gaming websites and platforms', 1),
    ('File Sharing', 'File sharing and hosting services', 3),
    ('Email', 'Email services and providers', 1),
    ('Malware', 'Known malware distribution sites', 5),
    ('Phishing', 'Known phishing sites', 5)
]

# Insert categories
for category in categories:
    try:
        cursor.execute(
            'INSERT INTO url_categories (name, description, risk_level) VALUES (?, ?, ?)',
            category
        )
    except sqlite3.IntegrityError:
        # Skip if category already exists
        pass

# Commit changes
conn.commit()
conn.close()

print("URL categories initialized successfully!")