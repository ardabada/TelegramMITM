using System;

namespace Telegram.Core.Network.Exceptions
{
    internal abstract class DataCenterMigrationException : Exception
    {
        internal int DC { get; private set; }

        protected DataCenterMigrationException(string msg, int dc) : base(msg)
        {
            DC = dc;
        }
    }
}
