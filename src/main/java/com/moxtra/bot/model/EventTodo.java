package com.moxtra.bot.model;

public class EventTodo extends EventBase {
	private String name;

	public EventTodo() {
	}
	
	public EventTodo(String id) {
		super(id);
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
