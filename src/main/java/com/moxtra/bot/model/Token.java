package com.moxtra.bot.model;

import java.io.Serializable;

public class Token implements Serializable {
	private String access_token;
	private Long exipred_time;

	
	public String getAccess_token() {
		return access_token;
	}
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}
	public Long getExipred_time() {
		return exipred_time;
	}
	public void setExipred_time(Long exipred_time) {
		this.exipred_time = exipred_time;
	}
}
