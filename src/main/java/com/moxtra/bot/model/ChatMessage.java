package com.moxtra.bot.model;

import java.io.Serializable;

public class ChatMessage implements Serializable {
	private String message_id;
	private String message_type;
	private String binder_id;
	private String bot_id;
	private String access_token;
	private Event event;

	
	public ChatMessage() {
	}
	
	public ChatMessage(String id) {
		message_id = id;
	}
	
	public String getBot_id() {
		return bot_id;
	}

	public void setBot_id(String bot_id) {
		this.bot_id = bot_id;
	}

	public String getAccess_token() {
		return access_token;
	}

	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}

	public String getBinder_id() {
		return binder_id;
	}

	public void setBinder_id(String binder_id) {
		this.binder_id = binder_id;
	}

	public String getMessage_id() {
		return message_id;
	}

	public void setMessage_id(String message_id) {
		this.message_id = message_id;
	}

	public String getMessage_type() {
		return message_type;
	}

	public void setMessage_type(String message_type) {
		this.message_type = message_type;
	}

	public Event getEvent() {
		return event;
	}

	public void setEvent(Event event) {
		this.event = event;
	}
}
