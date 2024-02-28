package com.test;

import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

public class TestApp {
	public static void main(String[] args) {
		TestApp tc = new TestApp();
	}
		
	public TestApp() {
		try
		{
          // Using Google Cloud APIs
		  Storage storage_service = StorageOptions.newBuilder().setProjectId("your-project-id")
			.build()
			.getService();	
		  for (Bucket b : storage_service.list().iterateAll()){
			  System.out.println(b);
		  }

		  // get arbitrary metadata values directly 
		  // unfortunately, its hardcoded here with a metadata.google.internal
		  // https://github.com/googleapis/sdk-platform-java/blob/main/java-core/google-cloud-core/src/main/java/com/google/cloud/MetadataConfig.java#L36
		  // so you have to use a raw httpclient
		  // System.out.println(com.google.cloud.MetadataConfig.getInstanceId());
		} 
		catch (Exception ex) {
			System.out.println("Error:  " + ex);
		}
	}
	    
}
