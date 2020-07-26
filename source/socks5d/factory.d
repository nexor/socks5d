module socks5d.factory;

import socks5d.driver : Application, Connection, ConnectionListener;

import socks5d.drivers.vibecore : VibeCoreApplication, VibeCoreConnection, VibeCoreConnectionListener, VibeCoreLogger;

alias ApplicationImpl        = VibeCoreApplication;
alias ConnectionImpl         = VibeCoreConnection;
alias ConnectionListenerImpl = VibeCoreConnectionListener;
alias LoggerImpl             = VibeCoreLogger;


/**
*/
@safe @nogc nothrow
@property
Factory f()
{
    return s_factory;
}

/**
*/
@safe @nogc nothrow
@property
LoggerImpl logger()
{
    return s_logger;
}

@safe
final class Factory
{
    Application application()
    {
        return new ApplicationImpl();
    }

    /**
    */
    Connection connection()
    {
        return new ConnectionImpl(logger);
    }

    /**
    */
    ConnectionListener connectionListener()
    {
        return new ConnectionListenerImpl(logger);
    }
}

static this()
{
    s_factory = new Factory;
    s_logger = new LoggerImpl;
}

private {
    Factory    s_factory;
    LoggerImpl s_logger;
}
