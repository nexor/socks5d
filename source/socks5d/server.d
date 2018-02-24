module socks5d.server;

import std.container.array;
import socks5d.client;
import socks5d.driver;
import socks5d.factory : f, logger;
import vibe.core.net;

struct ListenItem
{
    string host;
    ushort port;
}

struct AuthItem
{
    string login;
    string password;
}

nothrow
class Server
{
    private:
        string address;
        ushort port;
        shared static uint clientCounter = 0;

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
            foreach (item; listenItems) {
                logger.info("Listening %s:%d", item.host, item.port);
                listenTCP(item.port, &handleConnection, item.host);
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
            foreach (item; authItems) {
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
        nothrow
        void handleConnection(TCPConnection conn)
        {
            import core.atomic : atomicOp;

            try {
                atomicOp!"+="(clientCounter, 1);
                auto client = new Client(conn, clientCounter, this);

                client.run();
            } catch (Exception e) {
                scope (failure) assert(false);
                logger.error("Connection error: %s", e.msg);
            }
        }
}
