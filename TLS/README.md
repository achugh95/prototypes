A prototype to understand the internals of TLS/SSL. To make the most of out this, please go through the following the files:
- flow_diagram: overview of how the request flows.
- handshake.c: understanding how handshake happens actually.
- ssl_write.c: write flow. 
- ssl_read.c: read flow.
- consumer_handling.py: handling the errors at application level.
