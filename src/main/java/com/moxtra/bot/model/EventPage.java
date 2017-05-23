package com.moxtra.bot.model;

public class EventPage extends EventBase {
	private String type;

	public EventPage() {
	}
	
	public EventPage(String id) {
		super(id);
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
}