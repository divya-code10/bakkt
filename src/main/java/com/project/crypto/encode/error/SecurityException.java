package com.project.crypto.encode.error;

public class SecurityException extends Exception {

  SecurityException(String message ,Throwable err ){
	  super(message,err);
  }
}
