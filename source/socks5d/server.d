module socks5d.server;

import socks5d.client;
import std.socket;
import std.experimental.logger;
import core.thread : Thread;

struct ListenItem
{
    string host;
    ushort port;
    uint   backlog = 10;
}

struct AuthItem
{
    string login;
    string password;
}

class Server
{
    private:
        string address;
        ushort port;

        Client[] clients;
        uint clientCounter = 0;

        ListenItem[] listenItems;
        AuthItem[]   authItems;

    public:
        this(ListenItem[] listenItems = [], AuthItem[] authItems = [])
        {
            this.listenItems = listenItems;
            this.authItems = authItems;
        }

        final void run()
        {
            foreach (item; listenItems) {
                new Thread({
                    listen(item);
                }).start();
            }
        }

        void addListenItem(ListenItem item)
        {
            listenItems ~= item;
        }

        void addListenItem(string host, ushort port)
        {
            ListenItem item = {
                host: host,
                port: port,
            };

            listenItems ~= item;
        }

        void addAuthItem(AuthItem item)
        {
            authItems ~= item;
        }

        void addAuthItem(string login, string password)
        {
            AuthItem item = {
                login: login,
                password: password,
            };

            authItems ~= item;
        }

        nothrow
        bool authenticate(string login, string password)
        {
            foreach(item; authItems) {
                if (item.login == login && item.password == password) {
                    return true;
                }
            }

            return false;
        }

        bool hasAuthItems()
        {
            return authItems.length > 0;
        }

    protected:
        void listen(ListenItem listenItem)
        {
            auto socket = bindSocket(listenItem.host, listenItem.port, listenItem.backlog);

            while(true) {
                acceptClient(socket);
            }
        }

        TcpSocket bindSocket(string address, ushort port, uint backlog)
        {
            auto socket = new TcpSocket;
            assert(socket.isAlive);
            socket.bind(new InternetAddress(address, port));
            socket.listen(backlog);

            criticalf("Listening on %s", socket.localAddress().toString());

            return socket;
        }

        void acceptClient(Socket socket)
        {
            auto clientSocket = socket.accept();
            assert(clientSocket.isAlive);
            assert(socket.isAlive);

            clientCounter++;
            new Thread({
                auto client = new Client(clientSocket, clientCounter, this);
                clients ~= client;
                client.run();
            }).start();
        }
}
