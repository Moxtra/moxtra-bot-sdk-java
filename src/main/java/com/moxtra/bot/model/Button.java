package com.moxtra.bot.model;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Button implements Serializable {
	public static final String POSTBACK = "postback";
	public static final String ACCOUNT_LINK = "account_link";
	private String type = POSTBACK;
	private String text;
	private String payload;
	
	public Button() {
	}

	public Button(String text) {
		setText(text);
	}
	
	public Button(String type, String text) {
		setType(type);
		setText(text);
	}
	
	public Button(String type, String text, String payload) {
		setType(type);
		this.text = text;
		this.payload = payload;
	}
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		if (type != null && ACCOUNT_LINK.equalsIgnoreCase(type)) {
			this.type = ACCOUNT_LINK;
		} 
	}
	public String getText() {
		return text;
	}
	public void setText(String text) {
		this.text = text;
		if (this.payload == null) {
			String ntext = text.replace("[^\\x20-\\x7E]+", "").toUpperCase();
			this.payload = "MOXTRABOT_" + ntext;
		}
	}
	public String getPayload() {
		return payload;
	}
	public void setPayload(String payload) {
		this.payload = payload;
	}
}
