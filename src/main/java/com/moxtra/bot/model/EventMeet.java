package com.moxtra.bot.model;

public class EventMeet extends EventBase {
	private String topic;    // topic
	private String recording_url;
	private String start_time;
	private String end_time;

	public EventMeet() {
	}
	
	public EventMeet(String id) {
		super(id);
	}

	public String getTopic() {
		return topic;
	}

	public void setTopic(String topic) {
		this.topic = topic;
	}

	public String getRecording_url() {
		return recording_url;
	}

	public void setRecording_url(String recording_url) {
		this.recording_url = recording_url;
	}

	public String getStart_time() {
		return start_time;
	}

	public void setStart_time(String start_time) {
		this.start_time = start_time;
	}

	public String getEnd_time() {
		return end_time;
	}

	public void setEnd_time(String end_time) {
		this.end_time = end_time;
	}
}
