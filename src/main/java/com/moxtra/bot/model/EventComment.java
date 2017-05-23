package com.moxtra.bot.model;

public class EventComment extends EventBase {
	private String text;
	private String richtext;
	private String audio;

	public EventComment() {
	}
	
	public EventComment(String id) {
		super(id);
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

	public String getAudio() {
		return audio;
	}

	public void setAudio(String audio) {
		this.audio = audio;
	}
}
