using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Common;
using Microsoft.AspNetCore.Http;

namespace Server
{
    public class HMackMiddleware
    {
        private readonly RequestDelegate _next;

        public static string HMacProtect(HMacProtectData signData)
        {
            var encoding = Encoding.ASCII;
            return Convert.ToBase64String(new HMACSHA1(encoding.GetBytes(signData.Secret)).ComputeHash(encoding.GetBytes(signData.PlainData)));
        }

        public HMackMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext ctx)
        {
            try
            {
                //capture the current time
                var timeNow = DateTime.UtcNow.UnixTimeStampTime();

                //read data from url
                var terminal = ctx.Request.Query["terminal"];
                var time = ctx.Request.Query["time"];
                var key = ctx.Request.Query["key"];

                //recreate the key for validation
                var key2 = HMacProtect(new HMacProtectData {PlainData = $"{terminal}{time}", Secret = "password"});

                //calculate seconds between now and client sent in time
                var secondsBetweenCalls = timeNow - int.Parse(time);

                //if key are equal and key isn't older than 5 seconds, let it pass
                if (key == key2 && secondsBetweenCalls <= 5)
                {
                    await _next(ctx);
                }
                else
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await ctx.Response.WriteAsync("");
                }
            }
            catch (Exception)
            {                
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsync("");
            }
        }


    }
}
