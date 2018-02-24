module socks5d.server;

import std.container.array;
import socks5d.client;
import socks5d.driver;
import socks5d.factory : f, logger;

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

        Array!Client clients;
        uint clientCounter = 0;

        Array!ListenItem listenItems;
        Array!AuthItem   authItems;

    public:
        @nogc
        this(ListenItem[] listenItems = [], AuthItem[] authItems = [])
        {
            this.listenItems = listenItems;
            this.authItems = authItems;
        }

        final void run()
        {
            import core.thread : Thread;

            foreach (item; listenItems) {
                new Thread({
                    auto listener =  f.connectionListener();
                    logger.info("Listening on %s:%d", item.host, item.port);
                    listener.listen(item.host, item.port, &onClient);
                }).start();
            }
        }

        @nogc
        void addListenItem(ListenItem item)
        {
            listenItems ~= item;
        }

        @nogc
        void addListenItem(string host, ushort port)
        {
            ListenItem item = {
                host: host,
                port: port,
            };

            listenItems ~= item;
        }

        nothrow @nogc
        void addAuthItem(AuthItem item)
        {
            authItems ~= item;
        }

        nothrow @nogc
        void addAuthItem(string login, string password)
        {
            AuthItem item = {
                login: login,
                password: password,
            };

            authItems ~= item;
        }

        nothrow @nogc
        bool authenticate(string login, string password)
        {
            foreach(item; authItems) {
                if (item.login == login && item.password == password) {
                    return true;
                }
            }

            return false;
        }

        pure nothrow @safe @nogc
        bool hasAuthItems()
        {
            return authItems.length > 0;
        }

    protected:
        void onClient(Connection conn)
        {
            clientCounter++;
            logger.debugN("Got client %d", clientCounter);
            auto client = new Client(conn, clientCounter, this);
            client.run();
        }
}
