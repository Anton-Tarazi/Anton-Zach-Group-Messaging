# TODO
- [ ] Augment Server to handle message passing between client connections


We need individual HandleConnection threads to be able to send messages
to threads in charge of other connections to send them. HandleConnection
currently handles Login, Register, and then disconnects with the client.

Once a thread sends a message for another thread:
1. the sender handler needs to figure out which recipient handler corresponds to the recipient of the message
2. the server needs to put that message in a queue for the recipient handler to consume
3. the server needs to alert the recipient handler to consume it
4. the recipient handler must consume the message, package it for the recipient client
and send it to onto the network via the correct tcp socket.