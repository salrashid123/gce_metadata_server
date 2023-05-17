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
            Console.ReadKey();
        }

        private async Task Run()
        {    

            var googleCredential = await GoogleCredential.GetApplicationDefaultAsync().ConfigureAwait(false);
            ICredential credential = googleCredential.UnderlyingCredential;
            ComputeCredential computeCredential =  credential as ComputeCredential;
            if (await ComputeCredential.IsRunningOnComputeEngine().ConfigureAwait(false)) {
                // 
                // TODO, use the metadata to derive the projetid 
                // returns null: Google.Api.Gax.Platform.Instance().ProjectId

                var projectID = Google.Api.Gax.Platform.Instance().ProjectId; // "mineral-minutia-820";           
                var storage = StorageClient.Create();
                var buckets = storage.ListBuckets(projectID);
                Console.WriteLine("Buckets:");
                foreach (var bucket in buckets)
                {
                    Console.WriteLine(bucket.Name);
                }
            } else {
                Console.WriteLine("not on gce");
                return;
            }

        }

    }
}

