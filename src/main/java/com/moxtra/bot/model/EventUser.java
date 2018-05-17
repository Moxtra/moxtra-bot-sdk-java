package com.moxtra.bot.model;

public class EventUser extends EventBase {
	private String name;
	private String email;
	private String unique_id;
	private String image_url;
	private Boolean is_bot;

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

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUnique_id() {
		return unique_id;
	}

	public void setUnique_id(String unique_id) {
		this.unique_id = unique_id;
	}

	public String getImage_url() {
		return image_url;
	}

	public void setImage_url(String image_url) {
		this.image_url = image_url;
	}

	public Boolean getIs_bot() {
		return is_bot;
	}

	public void setIs_bot(Boolean is_bot) {
		this.is_bot = is_bot;
	}	
}