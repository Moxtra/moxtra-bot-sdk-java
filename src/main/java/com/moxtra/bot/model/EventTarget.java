package com.moxtra.bot.model;

public class EventTarget extends EventBase {
	private String object_type;

	public EventTarget() {
	}
	
	public EventTarget(String id, String type) {
		super(id);
		object_type = type;
	}

	public String getObject_type() {
		return object_type;
	}
	public void setObject_type(String object_type) {
		this.object_type = object_type;
	}

}