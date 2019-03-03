module socks5d.server;

import std.container.array;
import socks5d.client;
import socks5d.driver;
import socks5d.factory : f, logger;
import socks5d.auth;

struct ListenItem
{
    string host;
    ushort port;
}

class Server
{
    private:
        string address;
        ushort port;

        Array!Client clients;
        static shared uint clientCounter = 0;

        Array!ListenItem listenItems;

    package AuthManager authManager;

    public:
        uint id;

        @nogc
        this(ListenItem[] listenItems, AuthManager authManager)
        in {
            assert(authManager !is null);
        } body
        {


            this.listenItems = listenItems;
            this.authManager = authManager;
        }

        final void run()
        {
            import std.algorithm.iteration : map, filter;
            import std.traits;

            logger.diagnostic("Available auth methods: %s",   authManager.getSupportedMethods());

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





    protected:
        void onClient(Connection conn)
        {
            import core.atomic : atomicOp;

            atomicOp!"+="(clientCounter, 1);
            logger.debugN("Got client %d", clientCounter);

            try {
                auto client = new Client(conn, clientCounter, this.authManager);
                client.run();
            } catch (Exception e) {
                scope (failure) assert(false);
                conn.close();
                logger.error("Connection error: %s", e.msg);
                debug logger.error("%s", e.info);
            }
        }
}

Server createDefaultServer(string address, ushort port)
{
    auto authManager = new DefaultAuthManager();
    authManager.add(new NoAuthMethodHandler());

    auto server = new Server([], authManager);

    server.addListenItem(address, port);

    return server;
}
