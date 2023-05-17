const {Storage} = require('@google-cloud/storage');
const gcpMetadata = require('gcp-metadata');
var log4js = require("log4js");
var logger = log4js.getLogger();

async function main() {
  const isAvailable = await gcpMetadata.isAvailable();
  console.log(`Is available: ${isAvailable}`);

  if (isAvailable) {
    const projectId = await gcpMetadata.project('project-id');
    const storage = new Storage({
      projectId: projectId,
    });

    storage.getBuckets(function (err, buckets) {
      if (!err) {
        buckets.forEach(function (value) {
          logger.info(value.id);
        });
      }
    });
  }
}

main().catch(console.error);