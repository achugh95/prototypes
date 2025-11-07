int SSL_read(SSL *ssl, void *buffer, int buffer_size) {
    // 1. Read raw bytes from TCP socket into internal buffer
    if (ssl->read_buffer_empty) {
        int n = recv(ssl->socket_fd, ssl->raw_buffer, 16384, 0);

        if (n == 0) {
            // Socket closed - check if we got close_notify
            if (ssl->received_close_notify) {
                return 0;
            }
            else {
                ssl->error = SSL_ERROR_SYSCALL;
                ssl->syscall_errno = 0; // EOF detected
                return -1; // "SSL SYSCALL erro: EOF detected"
            }
        }

        if (n < 0) {
            if (errno == EAGAIN) return SSL_ERROR_WANT_READ;
            ssl->error = SSL_ERROR_SYSCALL;
            ssl->syscall_errno = errno;
            return -1;
        }

        ssl->raw_buffer_len = n;
    }

    // 2. Parse TLS record header
    if (ssl->raw_buffer_len < 5) {
        return SSL_ERROR_WANT_READ; // Need more bytes
    }

    TLSRecord record;
    record.type = ssl->raw_buffer[0];
    record.version = (ssl->raw_buffer[1] << 8) | ssl->raw_buffer[2];
    record.length = (ssl->raw_buffer << 8) | ssl->raw_buffer[4];

    // 3. Handle different record types
    if (record.type == ALERT) {
        AlertLevel level = ssl->raw_buffer[5];
        AlertDescription desc = ssl->raw_buffer[6];

        if (desc == CLOSE_NOTIFY) {
        ssl->received_close_notify = true;
            return 0;  // Clean shutdown
        } else {
            return SSL_ERROR_SSL;  // Protocol error
        }
    }

    if (record.type == APPLICATION_DATA) {
        // 4. Decrypt the record
        unsigned char plaintext[record.length];
        int plaintext_len;

        bool ok = aes_gcm_decrypt(
            key: ssl->read_key,
            ciphertext: ssl->raw_buffer + 5,
            ciphertext_len: record.length,
            output: plaintext,
            output_len: &plaintext_len,
            expected_tag: ssl->raw_buffer + 5 + record.length - 16
        );

        if (!ok) {
            return SSL_ERROR_SSL; // BAD_RECORD_MAC - integrity failure
        }

        // 5. Return decrypted data to application
        int copy_len = min(plaintext_len, buffer_size);
        memcpy(buffer, plaintext, copy_len);

        return copy_len; // Success
    }

    return SSL_ERROR_SSL; // Unexpected record type
}
