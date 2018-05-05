module socks5d.server;

import std.container.array;
import socks5d.client;
import socks5d.driver;
import socks5d.factory : f, logger;
import socks5d.packets: AuthMethodCollection, AuthMethod;

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

class Server
{
    private:
        string address;
        ushort port;

        Array!Client clients;
        static shared uint clientCounter = 0;

        Array!ListenItem listenItems;
        Array!AuthItem   authItems;
        AuthMethodCollection authMethods;
    public:
        uint id;

        @nogc
        this(ListenItem[] listenItems = [], AuthItem[] authItems = [])
        {
            this.listenItems = listenItems;
            this.authItems = authItems;
        }

        final void run()
        {
            authMethods = new AuthMethodCollection();

            if (hasAuthItems()) {
                authMethods += AuthMethod.AUTH;
            } else {
                authMethods += AuthMethod.NOAUTH;
            }

            logger.diagnostic("Available auth methods: %s", authMethods[]);

            foreach (item; listenItems) {
                auto listener = f.connectionListener();
                logger.info("Listening on %s:%d", item.host, item.port);
                listener.listen(item.host, item.port, &onClient);
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
        void onClient(Connection conn)
        {
            import core.atomic : atomicOp;

            atomicOp!"+="(clientCounter, 1);
            logger.debugN("Got client %d", clientCounter);

            try {
                auto client = new Client(conn, clientCounter, this);
                client.authMethods = authMethods;
                client.run();
            } catch (Exception e) {
                scope (failure) assert(false);
                conn.close();
                logger.error("Connection error: %s", e.msg);
                debug logger.error("%s", e.info);
            }
        }
}
