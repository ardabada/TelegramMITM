using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Telegram.Core;

namespace Demo
{
	class Program
	{
		static async Task Main(string[] args)
		{
			var client = new TelegramClient();
			await client.ConnectAsync();

			Console.WriteLine("done");
			Console.ReadLine();
		}
	}
}
