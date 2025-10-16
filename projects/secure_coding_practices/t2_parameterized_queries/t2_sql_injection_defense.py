import sqlite3

# Create a mock database and table where we can simulate attacks and defenses
def setup_db(db_name=":memory:"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT
        )
    """)

    users = [
        (1, 'theo_zel', 'tbr@corp.com'),
        (2, 'john_bri', 'jb@corp.com'),
        (3, 'data_base', 'db@corp.com')
    ]
    cursor.executemany("INSERT INTO users VALUES (?, ?, ?)", users)
    conn.commit()
    print("In-memory database created and populated with 3 users.")
    return conn

# INSECURE (VULNERABLE) FUNCTION  -OWASP Risk: A03: Injection

def get_user_insecure(conn, user_id_input: str):
    """
    Vulnerable function demonstrating a SQL Injection risk by using direct string concatenation.
    The database command structure is modified by user input.
    
    :param conn: The database connection object.
    :param user_id_input: User-supplied input string.
    """
    print(f"\n Querying for user ID: {user_id_input}")
    
    # VULNERABLE CODE: The user input is concatenated directly into the query.
    sql_query = f"SELECT username, email FROM users WHERE id = {user_id_input}"
    
    try:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        result = cursor.fetchall()
        return result
    except sqlite3.OperationalError as e:
        # This catches when the malicious input causes a syntax error
        print(f"[ERROR] SQL Operational Error: {e}")
        return None

# SECURE (PARAMETERIZED) FUNCTION
# OWASP Defense: Parameterized Queries (Separation of Code and Data)
def get_user_secure(conn, user_id_input: str):
    """
    Secure function using parameterized queries (placeholders).
    The database driver treats the user input as pure data, preventing execution of malicious code.
    
    :param conn: The database connection object.
    :param user_id_input: User-supplied input string.
    """
    print(f"\n[SECURE] Querying for user ID: {user_id_input}")
    
    # SECURE CODE: The query uses a placeholder (?) for the value.
    sql_query = "SELECT username, email FROM users WHERE id = ?"
    
    try:
        cursor = conn.cursor()
        # The input is passed separately as a tuple, ensuring it is treated as data, not code.
        cursor.execute(sql_query, (user_id_input,))
        result = cursor.fetchall()
        return result
    except sqlite3.Error as e:
        print(f"[ERROR] Database Error: {e}")
        return None



if __name__ == "__main__":
    db_connection = setup_db()
    
    #1. Normal Test Case: Harmless Input
    print("\n\nTEST 1: Normal Input (ID=3)")
    
    secure_result = get_user_secure(db_connection, '3')
    print(f"[SECURE] Result: {secure_result} (Expected: data_base)")
    
    insecure_result = get_user_insecure(db_connection, '3')
    print(f"[INSECURE] Result: {insecure_result} (Expected: data_base)")

    # 2. Malicious Test Case: SQL Injection Payload
    # Payload: ' OR '1'='1 -- 
    # This input is designed to: 
    # 1. Close the quote/numeric field, 
    # 2. Append a always-true condition ('1'='1'), and 
    # 3. Use '--' to comment out the rest of the original WHERE clause.
    # Result: The INSECURE query should return ALL users.
    malicious_input = "2 OR 1=1 --"
    
    print("\n\nTEST 2: SQL INJECTION ATTEMPT (Malicious Input)")

    # SECURE TEST: The entire input string is treated as the ID value. 
    # Since no user has the literal ID "2 OR 1=1 --", the result will be safe (empty).
    print("\nTesting SECURE Function")
    secure_exploit_result = get_user_secure(db_connection, malicious_input)
    print(f"[SECURE] Result (Expected Safe/Empty): {secure_exploit_result}")
    
    # INSECURE TEST: The SQL structure is compromised, leading to a critical data breach (all users returned).
    print("\nTesting INSECURE Function")
    insecure_exploit_result = get_user_insecure(db_connection, malicious_input)
    print(f"[INSECURE] Result (VULNERABLE - Returned {len(insecure_exploit_result)} users): {insecure_exploit_result}")
    
    db_connection.close()
    
    # Final Conclusion
    print("\n\n---------------------------------")
    print("[CONCLUSION]")
    print("The **SECURE** parameterized query function correctly treated the malicious input as data and returned no unexpected results.")
    print("The **INSECURE** function was successfully exploited, demonstrating why string concatenation is a major security risk.")
    print("---------------------------------")