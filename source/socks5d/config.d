module socks5d.config;

import sdlang.parser;
import socks5d.server;
import socks5d.auth;
import socks5d.factory : logger;
import std.conv, std.file, std.algorithm.iteration;

Configuration loadConfig(string filename)
{
    auto source = cast(string)read(filename);
    auto conf = new Configuration;
    auto rootNode = new SDLRootTag(conf);

    logger.diagnostic("Parsing config file %s", filename);

    foreach (event; source.pullParseSource(filename)) {
        rootNode.parse(event);
    }

    return conf;
}

class Configuration
{
    protected:
        Server[uint] servers;

    public:
        Server[uint] getServers()
        {
            return servers;
        }

        bool addServer(uint id, Server server)
        {
            servers[id] = server;

            return true;
        }
}

private:

abstract class SDLTag
{
    protected:
        bool    isFinished = false;
        SDLTag currentNode;
        Configuration conf;

    public:
        this(Configuration conf)
        {
            this.conf = conf;
        }

        bool parse(ParserEvent event)
        {
            if (currentNode !is null) {
                currentNode.parse(event);
                if (currentNode.finished) {
                    onChildTagEnd(currentNode);
                    currentNode = null;
                }
            } else {
                final switch(event.kind) {
                    case ParserEvent.Kind.tagStart:
                        auto e = cast(TagStartEvent) event;
                        debug(Socks5dConfig)
                            logger.debugV("%s TagStartEvent: %s:%s @ %s",
                                typeid(this),
                                e.namespace,
                                e.name,
                                e.location);
                        onTagStart(e);
                        break;

                    case ParserEvent.Kind.tagEnd:
                        auto e = cast(TagEndEvent) event;
                        debug(Socks5dConfig)
                            logger.debugV("%s TagEndEvent", typeid(this));
                        onTagEnd(e);
                        assert(isFinished == true);
                        break;

                    case ParserEvent.Kind.value:
                        auto e = cast(ValueEvent) event;
                        debug(Socks5dConfig)
                            logger.debugV("%s ValueEvent: %s", typeid(this), e.value);
                        onValue(e);
                        break;

                    case ParserEvent.Kind.attribute:
                        auto e = cast(AttributeEvent) event;
                        debug(Socks5dConfig)
                            logger.debugV("%s AttributeEvent: %s:%s = %s", typeid(this), e.namespace, e.name, e.value);
                        onAttribute(e);
                        break;
                }
            }

            return true;
        }

        @property
        bool finished()
        {
            return isFinished;
        }

    protected:
        // start of child tag
        void onTagStart(TagStartEvent event)
        {
            assert(0, "Tags are not allowed in " ~ event.location.to!string);
        }

        // end of current tag
        void onTagEnd(TagEndEvent event)
        {
            // doing nothing
        }

        void onValue(ValueEvent event)
        {
            assert(0, "Tag can not have a value in " ~ event.location.to!string);
        }

        void onAttribute(AttributeEvent event)
        {
            assert(0, "Tag can not have attributes in " ~ event.location.to!string);
        }

        // end of child tag
        void onChildTagEnd(SDLTag node)
        {
            // doing nothing
        }
}

class SDLRootTag : SDLTag
{
    public:
        this(Configuration conf)
        {
            super(conf);
        }

    protected:
        override void onTagStart(TagStartEvent event)
        {
            switch (event.name) {
                case "server":
                    currentNode = new SDLServerTag(conf);
                    break;

                default:
                    assert(0, "Unknown key: " ~ event.name.to!string);
            }
        }
}

class SDLServerTag : SDLTag
{
    protected:
        Server server;
        static uint id;

    public:
        this(Configuration conf)
        {
            super(conf);

            server = new Server([], new DefaultAuthManager());
            id += 1;
        }

    protected:
        override void onTagStart(TagStartEvent event)
        {
            switch (event.name) {
                case "listen":
                    currentNode = new SDLServerListenTag(conf, server);
                    break;
                case "auth":
                    currentNode = new SDLServerAuthTag(conf, server);
                    break;
                default:
                    assert(0, "Unknown tag: " ~ event.name.to!string);
            }
        }

        override void onTagEnd(TagEndEvent event)
        {
            import socks5d.packets : AuthMethod;
            import socks5d.auth : NoAuthMethodHandler;

            if (!server.authManager.has(AuthMethod.AUTH)) {
                server.authManager.add(new NoAuthMethodHandler);
            }

            isFinished = true;
            conf.addServer(id, server);
        }
}

class SDLServerListenTag : SDLTag
{
    protected:
        Server server;
        string host;
        ushort port;

    public:
        this(Configuration conf, Server server)
        {
            super(conf);

            this.server = server;
        }

    protected:
        override void onTagEnd(TagEndEvent event)
        {
            isFinished = true;
            server.addListenItem(host, port);
        }

        override void onValue(ValueEvent event)
        {
            host = event.value.to!string;
        }

        override void onAttribute(AttributeEvent event)
        {
            switch (event.name) {
                case "port":
                    port = event.value.to!string.to!ushort;
                    break;

                default:
                    assert(0, "Unknown attribute: " ~ event.name.to!string);
            }
        }
}

class SDLServerAuthTag : SDLTag
{
    protected:
        Server server;
        string login;
        string password;

    public:
        this(Configuration conf, Server server)
        {
            super(conf);
            this.server = server;
        }

    protected:
        override void onTagEnd(TagEndEvent event)
        {
            import socks5d.packets : AuthMethod;
            import socks5d.auth : PlainAuthMethodHandler;

            isFinished = true;

            if (!server.authManager.has(AuthMethod.AUTH)) {
                server.authManager.add(new PlainAuthMethodHandler);
            }

            auto plainAuthHandler = cast(PlainAuthMethodHandler)server.authManager.getHandler(AuthMethod.AUTH);
            plainAuthHandler.addAuthItem(login, password);
        }

        override void onValue(ValueEvent event)
        {
            login = event.value.to!string;
        }

        override void onAttribute(AttributeEvent event)
        {
            switch (event.name) {
                case "password":
                    password = event.value.to!string;
                    break;

                default:
                    assert(0, "Unknown attribute: " ~ event.name.to!string);
            }
        }
}
