package com.fits.application.loginapplication;
        

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

@WebServlet
@Path("/myController")
public class MyController  extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	
    
    public MyController() {
        super();
    }
    @GET
    protected void doGet(@Context HttpServletRequest req, @Context HttpServletResponse response) throws ServletException, IOException {
         
        System.out.println("IN GET");
       
    }
 
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
         
    }
}
