import sqlite3

# Create database and tables
def init_db():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    # Create items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    ''')

    # Add example data
    cursor.execute('INSERT OR IGNORE INTO users (username, password, email) VALUES (?, ?, ?)', 
                   ('admin', generate_password_hash('adminpass'), 'admin@example.com'))
    cursor.execute('INSERT OR IGNORE INTO items (name) VALUES (?)', ('Sample Item',))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
