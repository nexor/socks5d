import socks5d.server;
import vibe.core.core;
import vibe.core.log;
import vibe.core.args;

immutable string versionString = "0.0.3";
//immutable string defaultAddress = "127.0.0.1";
immutable string defaultAddress = "0.0.0.0";
immutable ushort defaultPort = 1080;

ushort port = defaultPort;
string address = defaultAddress;
string authString;
byte   verbosity = 1; // log verbosity level
bool   ver;

int main(string[] args)
{
    logInfo("Starting socks5d server v. %s", versionString);

    auto server = new Server(address, port);
    server.setAuthString("user1:password1");
    server.run();

    return runApplication();
}
