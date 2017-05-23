package com.moxtra.bot.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Comment implements Serializable {
	private Message message;
	private List<Template> fields_template;

	private Comment(Builder builder) {
		message = builder.message;
		fields_template = builder.fields_template;
	}
	
    public Message getMessage() {
		return message;
	}

	public List<Template> getFields_template() {
		return fields_template;
	}

	public String toJSONString() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this);
    }	
	
	public static class Builder 
    {
		private Message message;
		private List<Template> fields_template;
		
		
		public Builder() {	
			message = new Message();
		}
		
		public Builder text(String text) {
			message.setText(text);
			return this;
		}
		
		public Builder richtext(String richtext) {
			message.setRichtext(richtext);
			return this;
		}
		
		public Builder fields(HashMap<String, String> fields) {
			message.setFields(fields);
			return this;
		}
		
		public Builder action(String action) {
			message.setAction(action);
			return this;
		}
		
		public Builder buttons(List<Button> buttons) {
			message.setButtons(buttons);
			return this;
		}
		
		public Builder addButton(Button button) {
			message.addButton(button);
			return this;
		}
		
		public Builder fields_template(List<Template> fields_template) {
			this.fields_template = fields_template;
			return this;
		}	
		
		public Builder addTemplate(Template template) {			
			if (this.fields_template == null) {
				this.fields_template = new ArrayList<Template>();
			}			
			this.fields_template.add(template);
			return this;
		}

        //Return the finally consrcuted Comment object
        public Comment build() {
            Comment comment =  new Comment(this);
            return comment;
        }		
    }
}
