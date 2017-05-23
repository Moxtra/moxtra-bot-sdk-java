package com.moxtra.bot.model;

public class EventUser extends EventBase {
	private String name;

	public EventUser() {
	}
	
	public EventUser(String id) {
		super(id);
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}