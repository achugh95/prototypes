int SSL_write(SSL *ssl, const void *data, int len){
    const unsigned char *app_data = data;
    int total_written = 0;

    while (total_written < len) {
        // Split into 16KB TLS records
        int chunk = min(len - total_written, 16384);

        // 1. Build TLS record
        TLSRecord record;
        record.type = APPLICATION_DATA; // 0x17
        record.version = TLS_1_2; // 0x0303
        record.length = chunk + MAC_SIZE + PADDING;

        // 2. Encrypt the chunk
        unsigned char ciphertext[chunk + MAC_SIZE + PADDING];
        aes_gcp_encrypt(
            key: ssl->write_key,
            plaintext: app_data + total_written,
            plaintext_len: chunk,
            output: ciphertext,
            tag: ciphertext + chunk // AED tag for integrity
        );

        // 3. Assemble final TLS record
        unsigned char tls_record[5 + record.length];
        tls_record[0] = record.type;
        tls_record[1..2] = record.version;
        tls_record[3..4] = record.length; // Big-endian
        memcpy(tls_record + 5, ciphertext, record.length);

        // 4. Send via TCP socket
        int n = send(ssl->socket_fd, tls_record, sizeof(tls_record), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return SSL_ERROR_WANT_WRITE; // Non-blocking socket
            }
            return SSL_ERROR_SYSCALL; // Real I/O error
        }

        if (n < sizeof(tls_record)) {
            // Partial write - buffer remaining bytes (rare)
            ssl->pending_write_buffer = tls_record + n;
        }
        total_written += chunk;
    }

    return total_written; // Success
}
