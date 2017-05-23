package com.moxtra.bot.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Message implements Serializable {
	public static final String ACTION_CHAT = "chat";
	public static final String ACTION_PAGE = "page";
	public static final String ACTION_TODO = "todo";
	private String text;
	private String richtext;
	private HashMap<String, String> fields;
	private String action;
	private List<Button> buttons;
	
	public Message() {		
	}
	public Message(String text) {
		this.text = text;
	}
	public String getText() {
		return text;
	}
	public void setText(String text) {
		this.text = text;
	}
	public String getRichtext() {
		return richtext;
	}
	public void setRichtext(String richtext) {
		this.richtext = richtext;
	}
	public HashMap<String, String> getFields() {
		return fields;
	}
	public void setFields(HashMap<String, String> fields) {
		this.fields = fields;
	}
	public String getAction() {
		return action;
	}
	public void setAction(String action) {
		if (action != null && ACTION_PAGE.equalsIgnoreCase(action)) {
			this.action = ACTION_PAGE;
		} else if (action != null && ACTION_TODO.equalsIgnoreCase(action)) {
			this.action = ACTION_TODO;
		} else {
			this.action = ACTION_CHAT;
		}
	}
	public List<Button> getButtons() {
		return buttons;
	}
	public void setButtons(List<Button> buttons) {
		this.buttons = buttons;
	}
	public void addButton(Button button) {
		if (this.buttons == null) {
			this.buttons = new ArrayList<Button>();
		}
		this.buttons.add(button);
	}	
}
