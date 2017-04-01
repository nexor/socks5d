module socks5d.server;

import socks5d.client;
import core.thread : Thread;
import std.socket;

class Server : Thread
{
    private:
        ushort port;
        int backlog;
        Socket socket;
        Client[] clients;

    public:
        this(ushort port = 1080, int backlog = 10)
        {
            this.port = port;
            this.backlog = backlog;

            super(&run);
        }

        final void run()
        {
            socket = new TcpSocket;
            assert(socket.isAlive);
            socket.bind(new InternetAddress(port));
            socket.listen(backlog);

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
