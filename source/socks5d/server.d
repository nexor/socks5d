module socks5d.server;

import socks5d.client;
import std.socket;
import std.experimental.logger;

class Server
{
    private:
        string address;
        ushort port;
        string authString;
        int backlog;
        Socket socket;
        Client[] clients;
        uint clientCounter = 0;

    public:
        this(string address, ushort port = 1080, int backlog = 10)
        {
            this.address = address;
            this.port = port;
            this.backlog = backlog;
        }

        void setAuthString(string authString)
        {
            this.authString = authString;
            if (authString.length > 1) {
                warningf("Using authentication string: %s", authString);
            }
        }

        final void run()
        {
            bindSocket();

            while (true) {
                acceptClient();
            }
        }

    protected:
        void bindSocket()
        {

            socket = new TcpSocket;
            assert(socket.isAlive);
            socket.bind(new InternetAddress(address, port));
            socket.listen(backlog);

            criticalf("Listening on %s", socket.localAddress().toString());
        }

        void acceptClient()
        {
            import core.thread : Thread;

            auto clientSocket = socket.accept();
            assert(clientSocket.isAlive);
            assert(socket.isAlive);

            clientCounter++;
            new Thread({
                auto client = new Client(clientSocket, clientCounter);
                client.setAuthString(authString);
                clients ~= client;
                client.run();
            }).start();
        }
}
