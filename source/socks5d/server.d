module socks5d.server;

import socks5d.client;
import core.thread : Thread;
import std.socket, std.stdio;

class Server : Thread
{
    private:
        string address;
        ushort port;
        int backlog;
        Socket socket;
        Client[] clients;

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

            writefln("Listening on %s:%d", socket.localAddress().toAddrString(), port);

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
        auto client = new Client(clientSocket);
        clients ~= client;
        client.start();
    }
}
