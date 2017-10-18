package com.moxtra.bot.model;

import java.io.Serializable;

public class AccountLink implements Serializable {
	private String user_id;
	private String username;
	private String binder_id;
	private String client_id;
	private String org_id;

	
	public String getUser_id() {
		return user_id;
	}
	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getBinder_id() {
		return binder_id;
	}
	public void setBinder_id(String binder_id) {
		this.binder_id = binder_id;
	}	
	public String getClient_id() {
		return client_id;
	}
	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}
	public String getOrg_id() {
		return org_id;
	}
	public void setOrg_id(String org_id) {
		this.org_id = org_id;
	}
}
