package com.moxtra.bot.model;

import java.io.Serializable;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Event implements Serializable {
	private String timestamp;
	private EventUser user;
	private EventBot bot;
	private EventComment comment;
	private EventAnnotate annotate;
	private EventFile file;
	private EventPage page;
	private EventMeet meet;
	private EventTodo todo;
	private EventPostback postback;
	private EventTarget target;
	private EventComment reply_to;

	/**
	 * @return the target
	 */
	public EventTarget getTarget() {
		return target;
	}
	/**
	 * @param target the target to set
	 */
	public void setTarget(EventTarget target) {
		this.target = target;
	}
	public String getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}
	public EventUser getUser() {
		return user;
	}
	public void setUser(EventUser user) {
		this.user = user;
	}
	public EventBot getBot() {
		return bot;
	}
	public void setBot(EventBot bot) {
		this.bot = bot;
	}
	public EventPostback getPostback() {
		return postback;
	}
	public void setPostback(EventPostback postback) {
		this.postback = postback;
	}
	public EventComment getComment() {
		return comment;
	}
	public void setComment(EventComment comment) {
		this.comment = comment;
	}
	public EventFile getFile() {
		return file;
	}
	public void setFile(EventFile file) {
		this.file = file;
	}
	public EventPage getPage() {
		return page;
	}
	public void setPage(EventPage page) {
		this.page = page;
	}
	public EventMeet getMeet() {
		return meet;
	}
	public void setMeet(EventMeet meet) {
		this.meet = meet;
	}
	public EventTodo getTodo() {
		return todo;
	}
	public void setTodo(EventTodo todo) {
		this.todo = todo;
	}
	public EventAnnotate getAnnotate() {
		return annotate;
	}
	public void setAnnotate(EventAnnotate annotate) {
		this.annotate = annotate;
	}
	public EventComment getReply_to() {
		return reply_to;
	}
	public void setReply_to(EventComment reply_to) {
		this.reply_to = reply_to;
	}
}
