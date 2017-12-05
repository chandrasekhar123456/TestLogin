package com.fits.application.loginapplication;

import static com.fits.framework.security.util.SecuritySessionKeyConstant.FITS_PASSWORD;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.FITS_USERNAME;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.NON_KIOSK_APPS;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.SECURITY_TOKEN;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.json.JSONObject;

import com.fits.framework.security.login.PasswordLoginProperties;
import com.fits.framework.security.util.ApplicationsTokens;
import com.fits.framework.security.util.ConfigException;
import com.fits.framework.security.util.SecurityCryptographicException;
import com.fits.framework.security.util.SecurityCryptographicUtil;
import com.fits.framework.security.util.SecurityToken;
import com.fits.framework.security.util.ServiceRMIHelper;
import com.fits.framework.security.util.UserApplicationProfile;
import com.fits.service.applicationinteractionservice.remote.IApplicationInteractionServiceRMI;
import com.google.gson.Gson;

@Path("/loginapplicationREST")
public class LoginWebService {
	
	@Context
    private HttpServletRequest request;
 
    @Context
    private HttpServletResponse response;

	@GET
	
	public JSONObject  printMessage(@Context HttpServletRequest req, @Context HttpServletResponse res) throws ServletException, IOException {

		 JSONObject jsonObject = null;
		 init();
		 
		 PasswordLoginProperties plProperties;
	        HttpSession session = request.getSession();
	        String loginPageFullPath;
	        String loginPageRelativePath;
	        RequestDispatcher rd;
	        try {
	            plProperties = PasswordLoginProperties.getPasswordLoginProperties();
	            loginPageFullPath = plProperties.getLoginPageURL();
	            loginPageRelativePath = loginPageFullPath.substring(loginPageFullPath.lastIndexOf("/"));
	        } catch (ConfigException ce) {
	            throw new ServletException(ce);
	        }
	        String userName = request.getParameter(FITS_USERNAME);
	        String password = request.getParameter(FITS_PASSWORD);
try{
     	System.out.println("authenticate userName:" + userName);
         IApplicationInteractionServiceRMI aisRMI = (IApplicationInteractionServiceRMI) ServiceRMIHelper.getAISService();

         if(isTempPassword(password,userName)){
        	
        	 System.out.println("enforce change password:"+userName);
         	rd = request.getRequestDispatcher(CONSTANTS.CHANGE_PWD_URL);
         	request.setAttribute("pwd0", password);
         	request.setAttribute("userId", userName);

         	rd.forward(request, response);
         	return new JSONObject();
         }
         ApplicationsTokens applicationToken = null;
         String message  = null;
    	 try{
          applicationToken = aisRMI.getUserApplicationsTokens(userName, password);
    	 } catch(Exception e){
    		 message = e.getMessage();
    	 }
         session.setAttribute(SECURITY_TOKEN, applicationToken);

         if (applicationToken == null) {
        	 HashMap map = new HashMap();
        	 map.put("invalid", "Invalid Login details");
        	 jsonObject = new JSONObject(map);        	 
			 res.getWriter().print(jsonObject);
			 res.flushBuffer();

         } else {
        	
             plProperties.getApplicationListPageURL();
             HashMap applicationList = (HashMap) applicationToken.getApplicationList();
             HashMap applicationGroups = (HashMap) getApplicationGroups(applicationToken);
             String nonKioskApps = plProperties.getNonKioskApps();             
             session.setAttribute(NON_KIOSK_APPS, nonKioskApps);
             jsonObject = new JSONObject(applicationToken.getSecurityTokenMap());
             res.getWriter().print(jsonObject);
         }
         
        
		}catch(Exception e){
			//e.printStackTrace();
			System.out.println(e.getMessage());
						 //return jsonObject;
		}
		 return jsonObject;
	}
	
	public void init(){
		System.out.println("check serviceRMI.properties for AIS info");
        System.out.println("AIS client loaded from:" + IApplicationInteractionServiceRMI.class.getProtectionDomain().getCodeSource().getLocation());
        initProperties();
	}
	 public static void initProperties(){
	    	System.out.println("initProperties...");
	    	  InputStream in = null;
	    	  Properties props = new Properties ();
	    	  ClassLoader loader =  Thread.currentThread().getContextClassLoader ();

	    	  if (loader!=null) {
	    	    try {
	    	    System.out.println("loading:"+loader.getResource("loginapplication.properties"));

	    	      in = loader.getResourceAsStream("loginapplication.properties");
	    	      if (in != null) {
	    	        props.load (in);
	    	        CONSTANTS.version = props.getProperty ("version");
	    	        CONSTANTS.environment = props.getProperty("environment");
	    	        CONSTANTS.useActiveX = Boolean.valueOf(props.getProperty("useActiveX"));
	    	        CONSTANTS.hwphone = props.getProperty ("hwphone");
	    	        CONSTANTS.hwemail = props.getProperty ("hwemail");
	    	        CONSTANTS.defaultPassword = props.getProperty ("defaultPassword");

	    	        for (int i = 1; ; i++) {
	    	          String linkUrl = props.getProperty("link." + i + ".url");
	    	          if (linkUrl == null) {
	    	            break;
	    	          } else {
	    	            final Map<String, String> link = Collections.synchronizedMap(new HashMap<String, String>());
	    	            link.put("url", linkUrl);
	    	            link.put("label", props.getProperty("link." + i + ".label"));
	    	            link.put("location", props.getProperty("link." + i + ".location"));
	    	            CONSTANTS.links.put(linkUrl, link);
	    	            if(linkUrl.contains("ChangePassoword")){
	    	            	CONSTANTS.CHANGE_PWD_URL=linkUrl;
	    	            }
	    	          }
	    	        }

	    	        String chromeAppsStr = props.getProperty("chrome.applications");

	    	        if (chromeAppsStr != null) {
	    	          String[] appNames = chromeAppsStr.split(",");
	    	          for (int i = 0; i < appNames.length; i++) {
	    	        	  CONSTANTS.chromeApps.add(appNames[i].trim());
	    	          }
	    	        }
	    	        CONSTANTS.displayChromeAppsInIE = props.getProperty("displayChromeAppsInIE");
	    	      }
	    	    } catch (Exception e) {

	    	    } catch (Throwable t) {

	    	    } finally {
	    	      if (in != null) {
	    	        try {
						in.close();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	    	      }
	    	    }
	    	    CONSTANTS.initialized=true;
	    	    System.out.println(CONSTANTS.asString());

	    	  }
	    }
	 
	 public static Map getApplicationGroups(ApplicationsTokens apptok) {
	        Map<String, List<String>> groups = new HashMap<String, List<String>>(10);
	        if (apptok != null) {
	            Collection tokens = apptok.getSecurityTokenMap().values();
	            Iterator it = tokens.iterator();
	            Properties props;
	            while (it.hasNext()) {
	                UserApplicationProfile profile = (UserApplicationProfile) it.next();
	                SecurityToken token = profile.getSecurityToken();
	                String applicationName = profile.getApplicationName();
	                String displayName = applicationName;
	                String groupName = token.getGroupName();
	                String groupDisplayName = token.getGroupDisplayName();
	                props = profile.getProperties();
	                String standalone = props.getProperty("isstandalone") == null ? "true" : props.getProperty(
	                    "isstandalone");
	                if ("true".equalsIgnoreCase(standalone)) {
	                    if (groupName == null || groupName.trim().length() == 0) {
	                        groupName = applicationName;
	                    }
	                    List<String> group = groups.get(groupName);
	                    if (group == null) {
	                        group = new ArrayList<String>();
	                        if (displayName == null) {
	                            displayName = groupName;
	                        }
	                        group.add(displayName);
	                        groups.put(groupName, group);
	                    }
	                    if (groupName != null && groupDisplayName != null && groupDisplayName.trim().length() > 0) {
	                        group.set(0, groupDisplayName);
	                    }
	                    group.add(applicationName);
	                    group.add(profile.getSecurityToken().getURL());
	                }
	            }
	        }
	        return groups;
	    }
		public static boolean isTempPassword(String password, String userName) throws SecurityCryptographicException {
			return CONSTANTS.defaultPassword.equals(password)||validateTempPassword(userName, password);
		}
	    public  static boolean validateTempPassword(String userName,String tempPassword) {
			try {
				return tempPassword.equals(generateTempPasword(userName));
			} catch (Exception e) {
				System.out.println("error"+e);
				return false;
			}
		}
	    public  static String generateTempPasword(String userName) throws SecurityCryptographicException {
			return CONSTANTS.defaultPasswordPrefix+(SecurityCryptographicUtil.encryptString(userName.toLowerCase()).replaceAll("[^A-Za-z0-9]", "").replaceAll("[aeioux]", "ha").substring(0, 7));
		}
}
