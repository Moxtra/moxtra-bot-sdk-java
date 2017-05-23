package com.moxtra.bot.model;

public class EventBot extends EventBase {
	private String name;

	public EventBot() {
	}
	
	public EventBot(String id) {
		super(id);
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}