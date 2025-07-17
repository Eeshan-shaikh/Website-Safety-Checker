import sqlite3

def update_categories():
    """Update the database with security threat categories"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check if categories table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_categories'")
    if not cursor.fetchone():
        # Create the table if it doesn't exist
        cursor.execute('''
        CREATE TABLE url_categories (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            risk_level INTEGER DEFAULT 1
        )
        ''')
    
    # Define threat categories and risk levels
    threat_categories = [
        ("Legitimate", "Safe URLs with no detected threats", 0),
        ("Suspicious", "URLs that exhibit unusual patterns or behaviors, potentially indicating malicious intent", 2),
        ("Spam", "Links that lead to unsolicited content, often promoting products or services in a deceptive manner", 1),
        ("Phishing", "URLs designed to trick users into providing sensitive information by mimicking legitimate sites", 4),
        ("Malware", "Links that direct users to download harmful software or viruses", 5),
        ("Defacement", "URLs that host altered versions of legitimate websites, often for vandalism or misinformation", 3)
    ]
    
    # Try to insert new categories or update existing ones
    for name, description, risk_level in threat_categories:
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO url_categories (name, description, risk_level)
            VALUES (?, ?, ?)
            ''', (name, description, risk_level))
        except sqlite3.Error as e:
            print(f"Error inserting category {name}: {e}")
    
    conn.commit()
    conn.close()
    
    print("URL threat categories updated successfully!")

if __name__ == "__main__":
    update_categories()