package com.moxtra.bot.model;

public class EventFile extends EventBase {
	private String name;
	private String mimeType;

	public EventFile() {
	}
	
	public EventFile(String id) {
		super(id);
	}

	/**
	 * @return the mimeType
	 */
	public String getMimeType() {
		return mimeType;
	}

	/**
	 * @param mimeType the mimeType to set
	 */
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}