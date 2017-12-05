package com.fits.application.loginapplication;

import java.io.IOException;
import java.rmi.RemoteException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.fits.framework.security.util.ApplicationsTokens;
import com.fits.framework.security.util.SecurityCryptographicUtil;
import com.fits.framework.security.util.ServiceRMIHelper;
import com.fits.service.applicationinteractionservice.exceptions.AISSystemException;
import com.fits.service.applicationinteractionservice.exceptions.AuthenticationException;
import com.fits.service.applicationinteractionservice.exceptions.ProfileNotFoundException;
import com.fits.service.applicationinteractionservice.exceptions.UserNotFoundException;
import com.fits.service.applicationinteractionservice.remote.IApplicationInteractionServiceRMI;

public class ChangePasswordServlet extends HttpServlet {
	public static final Logger log = Logger.getLogger(ChangePasswordServlet.class.getName());

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException,
			IOException {
		// get posted information

		String message;
		try {
			String userName = request.getParameter("username");
			String oldPassowrd = request.getParameter("pwd0");
			String newPassword1 = request.getParameter("pwd1");
			String newPassowrd2 = request.getParameter("pwd2");
        	request.setAttribute("pwd0", oldPassowrd);
        	request.setAttribute("userId", userName);
			log.info("userName:" + userName
					+ "|oldPassowrd:" + SecurityCryptographicUtil.encryptString(oldPassowrd));
//					+ "|newPassword1:" + SecurityCryptographicUtil.encryptString(newPassword1)
//					+ "|newPassword2:" +SecurityCryptographicUtil.encryptString( newPassowrd2));
		if(!newPassword1.equals(newPassowrd2)){
			forwardWithMessage(request, response, "new passowrd don't match");
		}
		if(oldPassowrd.equals(newPassword1)){
			forwardWithMessage(request, response, "new passowrd identical to old password, please change");
		}

// authenticate
			IApplicationInteractionServiceRMI aisRMI = (IApplicationInteractionServiceRMI) ServiceRMIHelper
					.getAISService();
			if(FitsUserValidation.isTempPassword(oldPassowrd,userName)){
				oldPassowrd=CONSTANTS.defaultPassword;
			}
			aisRMI.updatePassword(userName, oldPassowrd, newPassword1);
			message = "Password changed successfully.";
		} catch (ProfileNotFoundException e) {
			message = "User Profile not found.";
			log.error("error", e);
		} catch (AuthenticationException e) {
			message = "Authentication failed.";
			log.error("error", e);
		} catch (UserNotFoundException e) {
			message = "User not found.";
			log.error("error", e);
		} catch (AISSystemException e) {
			message = "System Error.";
			log.error("error", e);
		} catch (Exception e) {
			message = "System error.";
			log.error("error", e);
		}

		forwardWithMessage(request, response, message);
	}

	private void forwardWithMessage(HttpServletRequest request, HttpServletResponse response, String message)
			throws ServletException, IOException {

		request.setAttribute("message", message);
		log.info("message:" + message);
		String toPage;
		if (message.toLowerCase().contains("successfully")) {
			toPage = "/LoginPage.jsp";
		} else {

			toPage = "/ChangePassoword.jsp";
		}
		request.getRequestDispatcher(toPage).forward(request, response);
	}

	private boolean isBlank(String field) {
		return ("" + field).length() > 0;
	}
}
