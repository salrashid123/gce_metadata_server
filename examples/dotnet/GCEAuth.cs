using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Google.Apis.Storage.v1.Data;
using Google.Cloud.Storage.V1;
using Google.Apis.Auth.OAuth2;

namespace AuthHarness
{
    internal class Program 
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                new Program().Run().Wait();
            }
            catch (AggregateException ex)
            {
                foreach (var err in ex.InnerExceptions)
                {
                    Console.WriteLine("ERROR: " + err.Message);
                }
            }
        }

        private async Task Run()
        {    

            var googleCredential = await GoogleCredential.GetApplicationDefaultAsync().ConfigureAwait(false);
            ICredential credential = googleCredential.UnderlyingCredential;
            ComputeCredential computeCredential =  credential as ComputeCredential;
            if (await ComputeCredential.IsRunningOnComputeEngine().ConfigureAwait(false)) {

                var projectID = Google.Api.Gax.Platform.Instance().ProjectId;           
                var storage = StorageClient.Create();
                var buckets = storage.ListBuckets(projectID);
                Console.WriteLine("Buckets:");
                foreach (var bucket in buckets)
                {
                    Console.WriteLine(bucket.Name);
                }

                // TODO: get metadata values directly without using a raw httpclient 
                // the following is limited to a few compute-centric values 
                // var instance_host = Google.Api.Gax.Platform.Instance().GceDetails;
                // Console.WriteLine(instance_host);    
            } else {
                Console.WriteLine("not on gce");
                return;
            }

        }

    }
}

