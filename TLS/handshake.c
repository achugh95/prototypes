// Application calls SSL_connect() after TCP socket is connected
int SSL_connect(SSL *ssl) {
    while (!handshake_complete) {
        // TLS library constructs handshake messages
        if (need_to_send_client_hello) {
            msg = build_client_hello(ssl->supported_ciphers);
            n = send(ssl->socket_fd, msg, msg_len, 0); // TCP send
            if (n < 0) return SSL_ERROR_SYSCALL; // Network error
        }

        // Read server's response
        n = recv(ssl->socket_fd, buffer, sizeof(buffer), 0);
        if (n == 0) return SSL_ERROR_SYSCALL; // Unexpected EOF
        if (n < 0 && errno == EAGAIN) return SSL_ERROR_WANT_READ;

        // Parse ServerHello, Certificate, ServerKeyExchange, etc.
        parse_handshake_message(buffer, n);

        // Verify server certificate
        if (!verify_certficate(ssl->peer_cert, ssl->ca_list)) {
            return SSL_ERROR_SSL; // Certificate validation failed
        }

        // Derive session keys from DH/ECDH exchange
        derive_session_keys(ssl);

        // Send ClientKeyExchange, ChangeCipherSpec, Finished
        // ... more send()/recv() rounds ...

        handshake_complete = true;
    }
    return SSL_SUCCESS;  // Handshake done, ready for application data
}
