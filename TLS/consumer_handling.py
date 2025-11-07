import psycopg2


conn = psycopg2.connect('db__connection_string')
cursor = conn.cursor()

# Application-level error handling
try:
    cursor.execute("SELECT ...")
except psycopg2.OperationalError as e:
    # libpq detected SSL I/O failure
    if "SSL SYSCALL error: EOF detected" in str(e):
        # Server closed TCP socket without close_notify
        # Could be: server crash, load balancer timeout, firewall drop
        print("Connection dropped unexpectedly")

    elif "certificate verify failed" in str(e):
        # Handshake failed during cert validation
        print("Server certificate invalid/untrusted")

    elif "Connection reset by peer" in str(e):
        # TCP RST received - server or middlebox killed connection
        print("Network disruption")
