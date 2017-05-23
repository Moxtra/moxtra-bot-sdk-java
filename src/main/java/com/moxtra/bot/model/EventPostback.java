package com.moxtra.bot.model;

public class EventPostback extends EventBase {
	private String text;
	private String payload;

	public EventPostback() {
	}
	
	public EventPostback(String id) {
		super(id);
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}
}