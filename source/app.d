import socks5d.server, socks5d.config;
import vibe.core.core;
import vibe.core.log;
import vibe.core.args;

immutable string versionString = "0.0.4";

ushort port = 1080;
string address = "127.0.0.1";
string authString;
string configFile = "config.sdl";
bool   ver;

int main(string[] args)
{
    logInfo("Starting socks5d server v. %s", versionString);

    auto configReader = new ConfigReader;
    configReader
        .setAddress(address)
        .setPort(port)
        .setAuthString(authString)
        .setConfigFile(configFile);

    auto server = configReader.buildServer();
    server.run();

    return runApplication();
}
