module socks5d.config;

import sdlang;
import socks5d.server;
import std.stdio;

class ConfigReader
{
    string address;
    ushort port;
    string authString;

    string configFile;

    public:
        ConfigReader setAddress(string address)
        {
            this.address = address;

            return this;
        }

        ConfigReader setPort(ushort port)
        {
            this.port = port;

            return this;
        }

        ConfigReader setConfigFile(string configFile)
        {
            this.configFile = configFile;

            return this;
        }

        ConfigReader setAuthString(string authString)
        {
            this.authString = authString;

            return this;
        }

        Server buildServer()
        {
            
            if (configFile !is null) {
                configureFromFile(configFile);
            }

            auto server = new Server(address, port);
            server.setAuthString(authString);

            return server;
        }

    protected:
        void configureFromFile(string filename)
        {
            Tag root = parseFile(filename);
            Tag server = root.expectTag("server");

            address = server.getTagValue!string("listen", "127.0.0.1");
            port = cast(ushort) server.getTagAttribute!int("listen", "port", 1080);

            string login = server.getTagAttribute!string("auth", "login", null);
            string password = server.getTagAttribute!string("auth", "password", null);
            authString = login ~ ":" ~ password;
        }
}