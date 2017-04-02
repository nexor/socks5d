module socks5d.server;

import socks5d.client;
import core.thread : Thread;
import std.socket, std.stdio;
import std.experimental.logger;

class Server : Thread
{
    private:
        string address;
        ushort port;
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

            super(&run);
        }

        final void run()
        {
            socket = new TcpSocket;
            assert(socket.isAlive);
            socket.bind(new InternetAddress(address, port));
            socket.listen(backlog);

            criticalf("Listening on %s", socket.localAddress().toString());

            while (true) {
                acceptClient();
                Thread.yield();
            }
        }

    void acceptClient()
    {
        auto clientSocket = socket.accept();
        assert(clientSocket.isAlive);
        assert(socket.isAlive);

        clientCounter++;
        auto client = new Client(clientSocket, clientCounter);
        clients ~= client;
        client.start();
    }
}
