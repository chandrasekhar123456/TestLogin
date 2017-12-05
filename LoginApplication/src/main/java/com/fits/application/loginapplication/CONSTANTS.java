package com.fits.application.loginapplication;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class CONSTANTS {
	 public static  boolean initialized=false;
	 public static  boolean useActiveX = false;
	 public static  String version = null;
	 public static  String environment = null;
	 public static  String hwphone = null;
	 public static  String hwemail = null;
	 public static  String CHANGE_PWD_URL = null;
	 public static  Map<String, Map<String, String>> links = Collections.synchronizedMap(new LinkedHashMap<String, Map<String, String>>());
	 public static  List<String> chromeApps = Collections.synchronizedList(new ArrayList<String>());
	 public static  String displayChromeAppsInIE = null;
	public static String defaultPassword=null;
	public static String defaultPasswordPrefix="default";

	 public static  String asString(){
		 return ("initialized:"+initialized+"|useActiveX:"+useActiveX+"|version:"+version+"|environment:"+environment+"|hwphone:"+hwphone+"|hwemail:"+hwemail+"\nlinks:"+links +"\nchromeApps:"+chromeApps+"\ndisplayChromeAppsInIE:"+displayChromeAppsInIE);


	 }

	 public static String getAbsoluteURL(String linkUrl,HttpServletRequest request){
	    	if(linkUrl.startsWith("/")){
	    		linkUrl=request.getContextPath()+linkUrl;

	    	}
	    	return linkUrl;
	 }
}
