module socks5d.server;

import socks5d.client;
import vibe.core.log;
import vibe.core.net;

class Server
{
    private:
        string address;
        ushort port;
        string authString;
        uint clientCounter = 0;

    public:
        this(string address, ushort port = 1080)
        {
            this.address = address;
            this.port = port;
        }

        void setAuthString(string authString)
        {
            this.authString = authString;
            if (authString.length > 1) {
                logWarn("Using authentication string: %s", authString);
            }
        }

        final void run()
        {
            logDiagnostic("Listening on %s:%d", address, port);
            listenTCP(port, &handleConnection, address);
        }

    protected:
        @safe nothrow
        void handleConnection(TCPConnection conn)
        {
            try {
                clientCounter += 1;
                auto client = new Client(conn, clientCounter);
                client.setAuthString(authString);

                client.run();
            } catch (Exception e) {
                scope (failure) assert(false);
                logError("Connection error: %s", e.msg);
            }

        }
}
