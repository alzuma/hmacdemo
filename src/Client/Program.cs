using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Common;

namespace Client
{
    public class Program
    {
        public static string HMacProtect(HMacProtectData signData)
        {
            var encoding = Encoding.ASCII;
            return Convert.ToBase64String(
                new HMACSHA1(
                    encoding.GetBytes(signData.Secret)
                ).ComputeHash(
                      encoding.GetBytes(signData.PlainData)));
        }

        public static void Main(string[] args)
        {
            RunAsync().Wait();
        }


        static async Task RunAsync()
        {
            
            //capture the current time
            var uxTime = DateTime.UtcNow.UnixTimeStampTime();

            //user name
            const string terminal = "t1";

            //create the cargo to protect
            var cargo = new HMacProtectData
            {
                PlainData = $"{terminal}{uxTime}",
                Secret = "password"
            };

            //create api key from cargo
            var apiKey = HttpUtility.UrlEncode(HMacProtect(cargo));

            var httpClient = new HttpClient();
            var uri = $"http://localhost:5000/api/values?key={apiKey}&time={uxTime}&terminal={terminal}";

            HttpResponseMessage response;
            try
            {
                response = await httpClient.GetAsync(uri);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                return;
            }
            
            Console.WriteLine($"StatusCode: {response.StatusCode}");            
            Console.ReadLine();
        }
    }
}
