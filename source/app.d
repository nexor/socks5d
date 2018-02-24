import std.getopt;
import socks5d.server, socks5d.config;
import socks5d.factory : f, logger;

immutable string versionString = "0.0.4-dev";
immutable string defaultAddress = "127.0.0.1";
immutable ushort defaultPort = 1080;

ushort port = defaultPort;
string address = defaultAddress;
string configFile;
byte   verbosity; // log verbosity level
bool   ver;

int main(string[] args)
{
    if (processHelpInformation(args)) {
        return 0;
    }

    bool correctLevel = logger.level(verbosity);
    if (!correctLevel) {
        logger.warning("Unknown verbosity level: %d", verbosity);
    }

    logger.info("Starting socks5d server v. %s", versionString);

    auto app = f.application();

    if (configFile is null) {
        logger.warning("config file not found, using default settings");

        auto server = new Server;

        server.addListenItem(address, port);
        app.addServer(server);

    } else if (!app.fileExists(configFile)) {
        logger.fatal("Config file '%s' not found, terminating.", configFile);
        return 1;
    } else {
        foreach (Server server; configFile.loadConfig.getServers()) {
            app.addServer(server);
        }
    }

    return app.run();
}

bool processHelpInformation(string[] args)
{
    import std.conv, std.stdio : writefln;

    const string helpString = "Socks5d SOCKS 5 proxy server version " ~ versionString ~ ".\n\n" ~
        "Usage: socks5d [OPTIONS]";

    auto helpInformation = getopt(args,
        std.getopt.config.caseSensitive,
        std.getopt.config.bundling,
        "address", "[IP address] Address to bind to (" ~ defaultAddress ~ " by default).",   &address,
        "port",    "[1..65535] Port number to listen to (" ~ to!string(defaultPort) ~ " by default).", &port,
        "config",  "[path] Path to config file.", &configFile,
        "version|V",  "Print version and exit.",     &ver,
        "verbose|v+",  "[0..3] Use verbose output level. Available levels: " ~
            "0(default, least verbose), 1, 2, 3(most verbose).",         &verbosity
    );

    if (ver) {
        writefln("Socks5d version %s", versionString);

        return true;
    }

    if (helpInformation.helpWanted) {
        defaultGetoptPrinter(helpString, helpInformation.options);
        return true;
    }

    return false;
}
