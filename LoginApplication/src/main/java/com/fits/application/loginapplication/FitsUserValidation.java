package com.fits.application.loginapplication;

import static com.fits.framework.security.util.SecuritySessionKeyConstant.FITS_PASSWORD;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.FITS_USERNAME;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.NON_KIOSK_APPS;
import static com.fits.framework.security.util.SecuritySessionKeyConstant.SECURITY_TOKEN;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.rmi.NotBoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.json.JSONObject;

import com.fits.framework.security.login.PasswordLoginProperties;
import com.fits.framework.security.util.ApplicationsTokens;
import com.fits.framework.security.util.ConfigException;
import com.fits.framework.security.util.SecurityCryptographicException;
import com.fits.framework.security.util.SecurityCryptographicUtil;
import com.fits.framework.security.util.SecurityToken;
import com.fits.framework.security.util.ServiceRMIHelper;
import com.fits.framework.security.util.ToXmlStringException;
import com.fits.framework.security.util.UserApplicationProfile;
import com.fits.service.applicationinteractionservice.exceptions.AISSystemException;
import com.fits.service.applicationinteractionservice.exceptions.AuthenticationException;
import com.fits.service.applicationinteractionservice.exceptions.ProfileNotFoundException;
import com.fits.service.applicationinteractionservice.exceptions.UserNotFoundException;
import com.fits.service.applicationinteractionservice.remote.IApplicationInteractionServiceRMI;
import com.google.gson.Gson;

public class FitsUserValidation extends HttpServlet  {
	/**
	 *
	 */
	private static final long serialVersionUID = 1L;
	public static final Logger logger =
			Logger.getLogger(FitsUserValidation.class.getName());

    public FitsUserValidation() {
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        logger.info("check serviceRMI.properties for AIS info");
        System.out.println("AIS client loaded from:" + IApplicationInteractionServiceRMI.class.getProtectionDomain().getCodeSource().getLocation());
        initProperties();
    }

    public void destroy() {
    }

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {


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


        try {
        	logger.info("authenticate userName:" + userName);
            IApplicationInteractionServiceRMI aisRMI = (IApplicationInteractionServiceRMI) ServiceRMIHelper.getAISService();

            if(isTempPassword(password,userName)){
            	logger.info("enforce change password:"+userName);
            	rd = request.getRequestDispatcher(CONSTANTS.CHANGE_PWD_URL);
            	request.setAttribute("pwd0", password);
            	request.setAttribute("userId", userName);

            	rd.forward(request, response);
            	return;
            }
            ApplicationsTokens applicationToken = aisRMI.getUserApplicationsTokens(userName, password);
            session.setAttribute(SECURITY_TOKEN, applicationToken);

            if (applicationToken == null) {
                rd = request.getRequestDispatcher(loginPageRelativePath);
            } else {
                plProperties.getApplicationListPageURL();
                String securityToken = applicationToken.toXmlString();
//                session.setAttribute(SECURITY_TOKEN, securityToken);
                HashMap applicationList = (HashMap) applicationToken.getApplicationList();
//                session.setAttribute(APPLICATION_LIST, applicationList);
                HashMap applicationGroups = (HashMap) getApplicationGroups(applicationToken);
//                session.setAttribute(APPLICATION_GROUPS, applicationGroups);
                String nonKioskApps = plProperties.getNonKioskApps();
                session.setAttribute(NON_KIOSK_APPS, nonKioskApps);
                Gson gson = new Gson(); 
                JSONObject jsonObject = new JSONObject(applicationGroups);

                String json = gson.toJson(applicationGroups);
                PrintWriter out =response.getWriter();
                response.setContentType("application/json");
                System.out.println(jsonObject);
              //  out.write(json);
                //out.print(json);
                out.print(jsonObject);
                out.flush();
               /* if (applicationGroups == null || applicationGroups.size() == 0) {
                    request.setAttribute("noApplications", "Y");
                    rd = request.getRequestDispatcher(loginPageRelativePath);
                } else {
                    rd = request.getRequestDispatcher(plProperties.getApplicationListPageURL());
                }*/
            }
            
            //rd.forward(request, response);
        } catch (NotBoundException exp) {
            logger.error("error:",exp);
            response.sendRedirect(plProperties.getLoginPageURL());
        } catch (ConfigException ce) {
            logger.error("error:",ce);
            response.sendRedirect(plProperties.getLoginPageURL());
        } catch (AISSystemException se) {
            logger.error("error:",se);
            response.sendRedirect(plProperties.getLoginPageURL());
        } catch (AuthenticationException ae) {
            logger.error("error:",ae);
            request.setAttribute("AuthenticationException", "Y");
            rd = getServletContext().getRequestDispatcher(loginPageRelativePath);
            rd.forward(request, response);
        } catch (ProfileNotFoundException pnf) {
            logger.error("error:",pnf);
            response.sendRedirect(plProperties.getLoginPageURL());
        } catch (ToXmlStringException tse) {
            logger.error("error:",tse);
            response.sendRedirect(plProperties.getLoginPageURL());
        } catch (UserNotFoundException e) {
        	 logger.error("error:",e);
             response.sendRedirect(plProperties.getLoginPageURL());
        } catch (Exception e) {
       	 logger.error("error:",e);
            response.sendRedirect(plProperties.getLoginPageURL());
		}
    }

	public static boolean isTempPassword(String password, String userName) throws SecurityCryptographicException {
		return CONSTANTS.defaultPassword.equals(password)||validateTempPassword(userName, password);
	}

    public  static String generateTempPasword(String userName) throws SecurityCryptographicException {
		return CONSTANTS.defaultPasswordPrefix+(SecurityCryptographicUtil.encryptString(userName.toLowerCase()).replaceAll("[^A-Za-z0-9]", "").replaceAll("[aeioux]", "ha").substring(0, 7));
	}

    public  static boolean validateTempPassword(String userName,String tempPassword) {
		try {
			return tempPassword.equals(generateTempPasword(userName));
		} catch (Exception e) {
			logger.error("error",e);
			return false;
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

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        processRequest(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        processRequest(request, response);
    }

    public String getServletInfo() {
        return "Validates Fits login UserName and Password";
    }

    public static void initProperties(){
    	logger.info("initProperties...");
    	  InputStream in = null;
    	  Properties props = new Properties ();
    	  ClassLoader loader =  Thread.currentThread().getContextClassLoader ();

    	  if (loader!=null) {
    	    try {
    	    logger.info("loading:"+loader.getResource("loginapplication.properties"));

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
    	    logger.info(CONSTANTS.asString());

    	  }
    }
}
