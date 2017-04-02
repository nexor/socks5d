import std.stdio, std.getopt;
import socks5d.server;
import std.experimental.logger;

immutable string versionString = "0.0.1";
immutable string defaultAddress = "127.0.0.1";
immutable ushort defaultPort = 1080;

ushort port = defaultPort;
string address = defaultAddress;
byte  verbosity; // log verbosity level
bool   ver;

int main(string[] args)
{

    if (processHelpInformation(args)) {
        return 0;
    }

    switch (verbosity) {
        case 0:
            sharedLog.logLevel = LogLevel.critical;
            break;
        case 1:
            sharedLog.logLevel = LogLevel.warning;
            break;
        case 2:
            sharedLog.logLevel = LogLevel.info;
            break;
        case 3:
            sharedLog.logLevel = LogLevel.trace;
            break;
        default:
            sharedLog.logLevel = LogLevel.critical;
            warningf("Unknown verbosity level: %d", verbosity);
    }

    startServer(address, port);

    return 0;
}

void startServer(string address, ushort port)
{
    logf(LogLevel.critical, "Starting socks5d server v. %s", versionString);

    auto server = new Server(address, port);
    server.start();
}


bool processHelpInformation(string[] args)
{
    import std.conv;
    const string helpString = "Socks5d SOCKS 5 proxy server version " ~ versionString ~ ".\n\n" ~
        "Usage: socks5d [OPTIONS]";

    auto helpInformation = getopt(args,
        std.getopt.config.caseSensitive,
        "address", "[IP address] Address to bind to (" ~ defaultAddress ~ " by default).",   &address,
        "port",    "[1..65535] Port number to listen to (" ~ to!string(defaultPort) ~ " by default).", &port,

        "version|V",  "Print version and exit.",     &ver,
        "verbose|v",  "[0..3] Use verbose output level. Available levels: " ~
            "0(default, least verbose), 1, 2, 3(most verbose)",         &verbosity
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
