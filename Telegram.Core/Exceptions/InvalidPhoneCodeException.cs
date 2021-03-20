using System;
namespace Telegram.Core.Exceptions
{
    public class InvalidPhoneCodeException : Exception
    {
        internal InvalidPhoneCodeException(string msg) : base(msg) { }
    }
}
