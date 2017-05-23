package com.moxtra.bot.model;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Template implements Serializable {
	public static final String TEXT = "text";
	public static final String RICHTEXT = "richtext";
	public static final String PAGE = "page";
	private String template_type = TEXT;
	private String template;
	
	public Template() {
	}
	
	public Template(String template) {
		this.template = template;
	}
	
	public Template(String template_type, String template) {
		setTemplate_type(template_type);
		this.template = template;
	}
	
	public String getTemplate_type() {
		return template_type;
	}
	public void setTemplate_type(String template_type) {
		if (template_type != null && RICHTEXT.equalsIgnoreCase(template_type)) {
			this.template_type = RICHTEXT;
		} else if (template_type != null && PAGE.equalsIgnoreCase(template_type)) {
			this.template_type = PAGE;
		}
	}
	public String getTemplate() {
		return template;
	}
	public void setTemplate(String template) {
		this.template = template;
	}
}
