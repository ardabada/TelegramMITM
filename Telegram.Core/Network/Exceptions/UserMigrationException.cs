namespace Telegram.Core.Network.Exceptions
{
    internal class UserMigrationException : DataCenterMigrationException
    {
        internal UserMigrationException(int dc)
            : base($"User located on a different DC: {dc}.", dc)
        {
        }
    }
}
