using System;
using Microsoft.AspNetCore.SignalR.Client;
using System.Threading.Tasks;
using System.Net;
using System.Runtime.CompilerServices;
using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using System.IO;

using log4net;
using log4net.Config;
using System.Reflection;
using System.Net.Http;
using Topshelf;

namespace AgentClient
{
    class Program
    {
        
        static async Task Main(string[] args)
        {
            
            // hapus file log.txt jika log lebih dari 1 bulan
            AutoDeleteFile();
            HostFactory.Run(x =>
            {
                x.Service<DeviceService>();
                x.EnableServiceRecovery(r => r.RestartService(TimeSpan.FromSeconds(10)));
                x.SetServiceName("DeviceService");
                x.StartAutomatically();

            });    
            
        }

        private static void AutoDeleteFile()
        {
            try
            {
                string directoryPath = @"D:\log.txt";
              
                if (System.IO.File.Exists(directoryPath))
                {

                    string[] files = Directory.GetFiles(@"D:\", "log.txt");
                    
                     foreach (string file in files)
                     {
                         FileInfo fi = new FileInfo(file);

                         if (fi.CreationTime < DateTime.Now.AddMonths(-1))
                         {
                             fi.Delete();
                         }
                     }
                    
                }
                

            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

        }

    }
}

