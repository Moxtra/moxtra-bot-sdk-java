package com.moxtra.bot.model;

public class EventComment extends EventBase {
	private String text;
	private String richtext;
	private String audio;
	private Boolean is_position_comment;

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

	public Boolean getIs_position_comment() {
		return is_position_comment;
	}

	public void setIs_position_comment(Boolean is_position_comment) {
		this.is_position_comment = is_position_comment;
	}
}
