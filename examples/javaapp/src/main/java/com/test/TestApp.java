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
		  Storage storage_service = StorageOptions.newBuilder()
			.build()
			.getService();	
		  for (Bucket b : storage_service.list().iterateAll()){
			  System.out.println(b);
		  }

		} 
		catch (Exception ex) {
			System.out.println("Error:  " + ex);
		}
	}
	    
}
