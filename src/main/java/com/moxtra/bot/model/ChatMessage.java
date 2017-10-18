package com.moxtra.bot.model;

import java.io.Serializable;

public class ChatMessage implements Serializable {
	private String message_id;
	private String message_type;
	private String binder_id;
	private String org_id;
	private String client_id;
	private Event event;

	
	public ChatMessage() {
	}
	
	public ChatMessage(String id) {
		message_id = id;
	}
	
	public String getBinder_id() {
		return binder_id;
	}

	public void setBinder_id(String binder_id) {
		this.binder_id = binder_id;
	}

	public String getOrg_id() {
		return org_id;
	}

	public void setOrg_id(String org_id) {
		this.org_id = org_id;
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String client_id) {
		this.client_id = client_id;
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
