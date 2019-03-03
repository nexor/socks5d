module socks5d.auth;

import std.container.array;
import socks5d.driver;
import socks5d.packets;
import socks5d.client;
import socks5d.factory : logger;

interface AuthManager
{
    void add(AuthMethodHandler);

    bool has(AuthMethod);

    bool has(AuthMethodHandler);

    AuthMethodHandler getHandler(AuthMethod);

    AuthMethod[] getSupportedMethods();

    AuthMethod resolveAuthMethod(AuthMethod[]);

    bool authenticate(Client);
}

interface AuthMethodHandler
{
    @property @nogc const
    AuthMethod id()
    out(result)
    {
        assert(result != AuthMethod.NOTAVAILABLE);
    }

    bool authenticate(Client client);
}

struct MethodIdentificationPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1] nmethods;
    ubyte[]  methods;

    void receive(Connection conn)
    {
        receiveVersion(conn);
        receiveBuffer(conn, nmethods, methods);
    }

    ubyte getNMethods()
    {
        return nmethods[0];
    }

    AuthMethod[] getAuthMethods()
    {
        return cast(AuthMethod[])methods;
    }

    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        MethodIdentificationPacket packet;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x05,
            0x01,
            AuthMethod.NOAUTH
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 5);
        assert(packet.getNMethods() == 1);
        assert(packet.getAuthMethods() == [AuthMethod.NOAUTH]);
    }
}

struct MethodSelectionPacket
{
    private struct MethodSelectionPacketFields
    {
        align(1):

        ubyte      ver    = 0x05;
        AuthMethod method;
    }

    mixin Socks5OutgoingPacket!MethodSelectionPacketFields;

    @property
    AuthMethod method()
    {
        return fields.method;
    }

    @property
    void method(AuthMethod method)
    {
        fields.method = method;
    }
}

struct AuthPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1]  ulen;
    ubyte[]   uname;
    ubyte[1]  plen;
    ubyte[]   passwd;

    void receive(Connection conn)
    {
        receiveVersion(conn, 0x01);
        receiveBuffer(conn, ulen, uname);
        receiveBuffer(conn, plen, passwd);
    }

    @property @nogc
    string login()
    {
        return cast(string)uname;
    }

    @property @nogc
    string password()
    {
        return cast(string)passwd;
    }

    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new AuthPacket;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x01,
            5,
            't', 'u', 's', 'e', 'r',
            7,
            't', 'p', 'a', 's', 's', 'w', 'd'
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 1);
        assert(packet.login ~ ":" ~ packet.password == "tuser:tpasswd");
    }
}

struct AuthStatusPacket
{
    private struct AuthStatusPacketFields
    {
        align(1):

        ubyte      ver    = 0x05;
        AuthStatus status = AuthStatus.YES;
    }

    mixin Socks5OutgoingPacket!AuthStatusPacketFields;

    @property
    AuthStatus status()
    {
        return fields.status;
    }

    @property
    void status(AuthStatus status)
    {
        fields.status = status;
    }
}

class DefaultAuthManager: AuthManager
{
    protected:
        AuthMethodHandler[AuthMethod.max] authMethodHandlers;

    public:
        void add(AuthMethodHandler handler)
        {
            authMethodHandlers[handler.id] = handler;
        }

        @nogc
        bool has(AuthMethod method)
        {
            return authMethodHandlers[method] !is null;
        }

        @nogc
        bool has(AuthMethodHandler methodHandler)
        {
            return authMethodHandlers[methodHandler.id] !is null;
        }

        @nogc
        AuthMethodHandler getHandler(AuthMethod authMethod)
        {
            return authMethodHandlers[authMethod];
        }

        AuthMethod[] getSupportedMethods()
        {
            import std.algorithm.iteration : filter;
            import std.traits;
            import std.array : array;

            enum allMethods = [EnumMembers!AuthMethod][0..$-1];

            return allMethods.filter!(m => has(m)).array;
        }

        @nogc
        AuthMethod resolveAuthMethod(AuthMethod[] availableMethods)
        {
            import std.algorithm.searching : find;

            auto authMethods = availableMethods.find!((a) => has(a));

            return authMethods.length ? authMethods[0] : AuthMethod.NOTAVAILABLE;
        }

        bool authenticate(Client client)
        {
            MethodIdentificationPacket identificationPacket = {
                connID: client.id,
            };
            client.receive(identificationPacket);

            logger.debugV("[%d] Client preferrable auth methods: %s",
                client.id,
                identificationPacket.getAuthMethods());

            MethodSelectionPacket packet2 = {
                connID: client.id,
            };
            packet2.method = resolveAuthMethod(identificationPacket.getAuthMethods);
            logger.debugV("[%d] Method found: %s", client.id, packet2.method);

            client.send(packet2);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                logger.diagnostic("[%d] No available method to authenticate.", client.id);
                return false;
            }

            return getHandler(packet2.method).authenticate(client);
        }

        unittest
        {
            class AuthHandler0: AuthMethodHandler
            {
                public:
                    AuthMethod id() const { return AuthMethod.NOAUTH; }
                    AuthStatus authenticate(AuthMethod) { return AuthStatus.NO; }
                    bool authenticate(Client) { return false; }
            }

            class AuthHandler2: AuthMethodHandler
            {
                public:
                    AuthMethod id() const { return AuthMethod.AUTH; }
                    AuthStatus authenticate(AuthMethod) { return AuthStatus.NO; }
                    bool authenticate(Client) { return 0; }
            }

            auto authManager = new DefaultAuthManager();
            auto handler0 = new AuthHandler0();
            auto handler2 = new AuthHandler2();

            authManager.add(handler0);
            authManager.add(handler2);

            assert(authManager.getSupportedMethods() == [AuthMethod.NOAUTH, AuthMethod.AUTH]);

            auto arguments = [
                [AuthMethod.GSSAPI, AuthMethod.NOAUTH, AuthMethod.AUTH],
                [AuthMethod.GSSAPI],
            ];
            auto expected = [
                AuthMethod.NOAUTH,
                AuthMethod.NOTAVAILABLE,
            ];
            assert(arguments.length == expected.length);

            foreach (i, argument; arguments) {
                assert(authManager.resolveAuthMethod(argument) == expected[i]);
            }
        }
}


class NoAuthMethodHandler: AuthMethodHandler
{
    public:
        const
        AuthMethod id()
        {
            return AuthMethod.NOAUTH;
        }

        bool authenticate(Client) { return true; }
}

/**
 * Login/password SOCKS authentication, see RFC 1929
 */

struct AuthItem
{
    string login;
    string password;
}

class PlainAuthMethodHandler: AuthMethodHandler
{
    protected:
        Array!AuthItem   authItems;

    public:
        const
        AuthMethod id()
        {
            return AuthMethod.AUTH;
        }

        @nogc
        void addAuthItem(AuthItem item)
        {
            authItems ~= item;
        }

        @nogc
        void addAuthItem(string login, string password)
        {
            AuthItem item = {
                login: login,
                password: password,
            };

            authItems ~= item;
        }

        bool authenticate(Client client)
        {
            AuthPacket authPacket;
            AuthStatusPacket authStatusPacket;

            client.receive(authPacket);
            logger.debugV("[%d] Client auth with credentials: %s:***",
                client.id,
                authPacket.login);

            if (findAuthItem(authPacket.login, authPacket.password)) {
                authStatusPacket.status = AuthStatus.YES;
                logger.diagnostic("[%d] Client successfully authenticated.", id);
            } else {
                authStatusPacket.status = AuthStatus.NO;
                logger.diagnostic("[%d] Client failed to authenticate.", id);
            }

            client.send(authStatusPacket);

            return authStatusPacket.status == AuthStatus.YES;
        }

        bool findAuthItem(string login, string password)
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
}
