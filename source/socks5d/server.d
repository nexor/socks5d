module socks5d.server;

import socks5d.client;
import vibe.core.log;
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

@safe nothrow
class Server
{
    private:
        string address;
        ushort port;
        shared static uint clientCounter = 0;

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
                logInfo("Listening %s:%d", item.host, item.port);
                listenTCP(item.port, &handleConnection, item.host);
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
            foreach (item; authItems) {
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
                logError("Connection error: %s", e.msg);
            }
        }
}
