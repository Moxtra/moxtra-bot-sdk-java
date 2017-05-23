package com.moxtra.bot.model;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.io.Serializable;

public class EventBase implements Serializable {
	private String id;
    public static final String PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    public static final TimeZone GMT_TIME_ZONE = TimeZone.getTimeZone("GMT");
	static SimpleDateFormat format = new SimpleDateFormat(PATTERN, Locale.US);

	static {
		format.setTimeZone(GMT_TIME_ZONE);
	}

	public synchronized static String getUTCTime(long time) {
		try {
			return format.format(time);
		} catch (Exception e) {
			return Long.toString(time);
		}
	}

	public synchronized static long getTime(String UTC_Time) {

		try {
			Date date = format.parse(UTC_Time);
			return date.getTime();
		} catch (Exception e) {
			return 0L;
		}
	}

	public EventBase(String id) {
		this.id = id;
	}

	public EventBase() {
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}


}
