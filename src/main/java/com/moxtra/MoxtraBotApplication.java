package com.moxtra;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.moxtra.bot.OAuth2;
import com.moxtra.examples.MyBot;




@RestController
@SpringBootApplication
public class MoxtraBotApplication {
	private static final Logger logger = LoggerFactory.getLogger(MoxtraBotApplication.class);

	@Autowired
	private MyBot bot; 
	
	// GET 
	@RequestMapping(value = "/webhooks", method = RequestMethod.GET)
	public void getRequest(HttpServletRequest request, HttpServletResponse response) {
		try {
			bot.handleGetRequest(request, response);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}	
	
	// POST
	@RequestMapping(value = "/webhooks", method = RequestMethod.POST)
	public void postRequest(HttpServletRequest request, HttpServletResponse response) {
		try {
			bot.handlePostRequest(request, response);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}	
	
	
	// OAuth2	
	@Autowired
	private OAuth2 oauth2; 

	// Auth
	@RequestMapping(value = "/auth", method = RequestMethod.GET)
	public void authRequest(HttpServletRequest request, HttpServletResponse response) {
		oauth2.auth(request, response);
	}	
	
	// Callback
	@RequestMapping(value = "/callback", method = RequestMethod.GET)
	public void redirectRequest(HttpServletRequest request, HttpServletResponse response) {
		oauth2.callback(request, response, bot);
	}	
	
	// Application	
	public static void main(String[] args) {
		SpringApplication.run(MoxtraBotApplication.class, args);
	}
}
