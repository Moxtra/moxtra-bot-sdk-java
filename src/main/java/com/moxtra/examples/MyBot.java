package com.moxtra.examples;

import java.io.File;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.regex.Matcher;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.moxtra.bot.Chat;
import com.moxtra.bot.MoxtraBot;
import com.moxtra.bot.annotation.EventHandler;
import com.moxtra.bot.model.AccountLink;
import com.moxtra.bot.model.Button;
import com.moxtra.bot.model.ChatMessage;
import com.moxtra.bot.model.Comment;
import com.moxtra.bot.model.EventType;
import com.moxtra.bot.model.Token;

@Component
public class MyBot extends MoxtraBot {
	private static final Logger logger = LoggerFactory.getLogger(MyBot.class);

	// key - binder_id + user_id;  value - Chat
	public HashMap<String, Chat> pendingResponse = new HashMap<String, Chat>();

	// key - user_id;  value - Chat
	public HashMap<String, Chat> pendingOAuth = new HashMap<String, Chat>();

	// key - user_id;  value - 3rd party access_token
	public HashMap<String, String> accountLinked = new HashMap<String, String>();


	@EventHandler(event = EventType.BOT_ENABLED)
	public void onBotEnabled(Chat chat) {
		String bot_name = chat.getBot().getName();

		logger.info("Bot {} enabled on {}", bot_name, chat.getOrg_id());
	}

	@EventHandler(event = EventType.BOT_DISABLED)
	public void onBotDisabled(Chat chat) {
		String bot_name = chat.getBot().getName();

		logger.info("Bot {} disabled on {}", bot_name, chat.getOrg_id());
	}

	@EventHandler(event = EventType.BOT_INSTALLED)
	public void onBotInstalled(Chat chat) {
		String username = chat.getUsername();
		String binder_id = chat.getBinder_id();
		String bot_name = chat.getBot().getName();

		// obtain access_token
		Token token = getAccessToken(chat.getClient_id(), chat.getOrg_id());
		chat.setAccess_token(token.getAccess_token());

		String message = "@" + username + " Welcome to " + bot_name + "!!" ;
		chat.sendRequest(new Comment.Builder().text(message).build());
	}

	@EventHandler(event = EventType.BOT_UNINSTALLED)
	public void onBotUninstalled(Chat chat) {
		String bot_name = chat.getBot().getName();
		String binder_id = chat.getBinder_id();
		
		logger.info("Bot {} uninstalled on {}", bot_name, binder_id);
	}

	@EventHandler(event = EventType.MESSAGE)
	public void onMessage(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getComment().getText();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		if (chat.getPrimatches() > 0) {
			logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
			return;
		}

		StringBuilder richtext = new StringBuilder();
		richtext.append("[table][tr][th][center]BBCode Info[/center][/th][/tr]");
		richtext.append("[tr][td][img=50x25]https://www.bbcode.org/images/lubeck_small.jpg[/img][/td][/tr][tr][td]From: [i]");
		richtext.append(username);
		richtext.append("[/i][/td][/tr][tr][td][color=Red]");
		richtext.append(text);
		richtext.append("[/color][/td][/tr][/table]");

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(new Comment.Builder().richtext(richtext.toString()).build());
	}

	@EventHandler(patterns = {"(schedule|plan|have)? meet", "meeting together"})
	public void onHears(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getComment().getText();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		if (chat.getPrimatches() > 0) {
			logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
			return;
		} else {
			Matcher matcher = chat.getMatcher();

			logger.info("message for @{} {} on {}", username, text, matcher.group(0));
		}

		// save chat in pendingResponse for account_link
		pendingResponse.put(chat.getBinder_id() + chat.getUser_id(), chat);

		Button account_link_button = new Button(Button.ACCOUNT_LINK, "Sign In");
		Button postback_button = new Button("Not Sure?");

		String message = "@" + username + " do you need to schedule a meet?";

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(new Comment.Builder().text(message).addButton(account_link_button)
				.addButton(postback_button).build());
	}

	@EventHandler(patterns = {"(multi|multiple|many|simple)? fields"})
	public void onFieldHears(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getComment().getText();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		if (chat.getPrimatches() > 0) {
			logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
			return;
		} else {
			Matcher matcher = chat.getMatcher();

			logger.info("message for @{} {} on {}", username, text, matcher.group(0));
		}

		HashMap<String, String> fieldsMap = new HashMap();
		fieldsMap.put("title", "BBCode Info");
		fieldsMap.put("from", username);
		fieldsMap.put("info", text);
		fieldsMap.put("image_url", "https://www.bbcode.org/images/lubeck_small.jpg");

		Comment comment = new Comment.Builder().fields(fieldsMap).build();

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(comment);
	}

	@EventHandler(patterns = {"(file|audio|attach)? upload", "attachment"})
	public void onUploadHears(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getComment().getText();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		if (chat.getPrimatches() > 0) {
			logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
			return;
		} else {
			Matcher matcher = chat.getMatcher();

			logger.info("message for @{} {} on {}", username, text, matcher.group(0));
		}

		String message = "@" + username + " upload files";

		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource("file/start.png").getFile());
		File audio = new File(classLoader.getResource("file/test_comment.3gpp").getFile());

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(new Comment.Builder().text(message).build(), file, audio);
	}

	@EventHandler(event = EventType.POSTBACK)
	public void onPostback(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getPostback().getText();
		String payload = chat.getPostback().getPayload();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		String message = "@" + username + " generic postback " + text + " " + payload;

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(new Comment.Builder().text(message).build());
	}

	@EventHandler(event = EventType.POSTBACK, text = "Not Sure?")
	public void onSpecificPostback(Chat chat) {
		String username = chat.getUsername();
		String text = chat.getPostback().getText();
		String payload = chat.getPostback().getPayload();
		String client_id = chat.getClient_id();
		String org_id = chat.getOrg_id();

		String message = "@" + username + " specific postback " + text + " " + payload;

		// obtain access_token
		Token token = getAccessToken(client_id, org_id);
		chat.setAccess_token(token.getAccess_token());

		chat.sendRequest(new Comment.Builder().text(message).build());
	}

	@EventHandler(event = EventType.ACCOUNT_LINK)
	public void onAccountLink(AccountLink accountLink, HttpServletResponse response) {
		String user_id = accountLink.getUser_id();
		String binder_id = accountLink.getBinder_id();
		String username = accountLink.getUsername();
		String client_id = accountLink.getClient_id();
		String org_id = accountLink.getOrg_id();

		// obtain pending response
		Chat chat = pendingResponse.get(binder_id + user_id);

		if (chat != null) {

			String message = "@" + username + " performs an account_link for user_id: " + user_id + " on binder_id: " + binder_id;

			// obtain access_token
			Token token = getAccessToken(chat.getClient_id(), chat.getOrg_id());
			chat.setAccess_token(token.getAccess_token());

			chat.sendRequest(new Comment.Builder().text(message).build());
		} else {
			chat = pendingOAuth.get(user_id);
		}

		String al_access_token = accountLinked.get(user_id);

		try {
			if (al_access_token != null) {

				// obtain access_token
				Token token = getAccessToken(client_id, org_id);

				String message = "@" + username + " has already obtained access_token from the 3rd party service!";

				if (chat == null) {
					logger.info("Unable to get pending request!");

					// create a new Chat
					chat = new Chat();

					chat.setAccess_token(token.getAccess_token());
					chat.sendRequest(new Comment.Builder().text(message).build());

				} else {
					chat.setAccess_token(token.getAccess_token());
					chat.sendRequest(new Comment.Builder().text(message).build());
				}

				// close window
				response.setContentType("text/html");
				PrintWriter out = response.getWriter();
				out.print("<html><head></head><body onload=\"javascript:window.close();\"></body></html>");
				out.flush();

			} else {

				pendingResponse.remove(binder_id + user_id);

				// save chat to the pendingOAuth
				pendingOAuth.put(user_id, chat);

				// redirect if needed
				Cookie myCookie = new Cookie("user_id", user_id);
				response.addCookie(myCookie);

				response.sendRedirect("/auth");
			}
		} catch (Exception e) {
			logger.error("Unable to handle account_link: " + e.getMessage());
		}
	}

	// after doing OAuth2 against the 3rd party service to obtain a user level access_token
	@EventHandler(event = EventType.ACCESS_TOKEN)
	public void onAccessToken(String access_token, HttpServletRequest request) {

		String user_id = null;
		Cookie[] cookies = request.getCookies();
		for (Cookie cookie : cookies) {

		  if (cookie.getName().equals("user_id")) {
			  user_id = cookie.getValue();
			  break;
		  }
		}

		Chat chat = null;
		if (user_id != null) {
			chat = pendingOAuth.get(user_id);

			// save linked accessToken
			accountLinked.put(user_id, access_token);
		}

		if (chat != null) {

			pendingOAuth.remove(user_id);

			// complete the pending request
			String username = chat.getUsername();
			String text = chat.getComment().getText();

			String message = "@" + username + " after account linked, bot will complete your request: " + text;

			// obtain access_token
			Token token = getAccessToken(chat.getClient_id(), chat.getOrg_id());
			chat.setAccess_token(token.getAccess_token());

			chat.sendRequest(new Comment.Builder().text(message).build());
		}
	}

}
