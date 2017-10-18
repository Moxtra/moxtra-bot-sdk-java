package com.moxtra.bot;


import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.moxtra.bot.annotation.EventHandler;
import com.moxtra.bot.model.AccountLink;
import com.moxtra.bot.model.ChatMessage;
import com.moxtra.bot.model.EventType;
import com.moxtra.bot.model.Token;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

public abstract class MoxtraBot {
	private static final Logger logger = LoggerFactory.getLogger(MoxtraBot.class);
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private boolean genericHandling = false;
	private boolean verifyPostSignature = false;	
	// key - org_id;  value - Token
	private HashMap<String, Token> moxtraAccessToken = new HashMap<String,Token>();
	public static String api_endpoint;

	
    /**
     * A Map of all methods annotated with {@link EventHandler} 
     * key - the {@link EventType#name()}
     * value - a list of {@link MethodWrapper}
     */
    private final Map<String, List<MethodWrapper>> eventToMethodsMap = new HashMap<>();
	
    @Value("${client_id}")
    private String client_id;

    @Value("${client_secret}")
    private String client_secret;
    
    @Value("${api_endpoint:https://api.grouphour.com/v1}")
    public void setApi_endpoint(String endpoint) {
        api_endpoint = endpoint;
    }
    
    public static String getApi_endpoint() {
		return api_endpoint;
	}

    public String getClient_id() {
		return client_id;
	}

	public String getClientSecret() {
    	return client_secret;
    }
    
	public boolean isGenericHandling() {
		return genericHandling;
	}

	public void setGenericHandling(boolean genericHandling) {
		this.genericHandling = genericHandling;
	}
	
	public boolean isVerifyPostSignature() {
		return verifyPostSignature;
	}

	public void setVerifyPostSignature(boolean verifyPostSignature) {
		this.verifyPostSignature = verifyPostSignature;
	}

	public MoxtraBot() {
        Method[] methods = this.getClass().getMethods();
        for (Method method : methods) {
            if (method.isAnnotationPresent(EventHandler.class)) {
            	EventHandler handler = method.getAnnotation(EventHandler.class);
                String[] patterns = handler.patterns();
                
                if (patterns.length == 0) { 
                	populateMethod(method, handler, "");                	
                } else {	
	                for (String pattern : patterns) {	                	
	                	populateMethod(method, handler, pattern);
	                }
	            }
            }
        }
    }	
    
    
    private void populateMethod(Method method, EventHandler handler, String pattern) {
    	
    	EventType eventType = handler.event();
        String text = handler.text();    	
    	
        MethodWrapper methodWrapper = new MethodWrapper();
        methodWrapper.setMethod(method);
        methodWrapper.setPattern(pattern);
        methodWrapper.setText(text);

        List<MethodWrapper> methodWrappers = eventToMethodsMap.get(eventType.name());

        if (methodWrappers == null) {
            methodWrappers = new ArrayList<>();
        }

        methodWrappers.add(methodWrapper);
        eventToMethodsMap.put(eventType.name(), methodWrappers);
    }

    /**
     * handle Get request
     * 
     * @throws Exception
     */
    public void handleGetRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
    	String message_type = request.getParameter("message_type");
    	
    	logger.info("Get Message: " + message_type);
  	
    	if ("account_link".equals(message_type)) { 		
    		String token = request.getParameter("account_link_token");
    		
    		try {
    			List<MethodWrapper> methodWrappers = eventToMethodsMap.get(EventType.ACCOUNT_LINK.name());
    	        if (methodWrappers != null) {
		            io.jsonwebtoken.Claims body = Jwts.parser()
		                    .setSigningKey(this.client_secret.getBytes("UTF-8"))
		                    .parseClaimsJws(token)
		                    .getBody();
		            
		            AccountLink accountLink = new AccountLink();
		            accountLink.setUser_id((String) body.get("user_id"));
		            accountLink.setUsername((String) body.get("username"));
		            accountLink.setBinder_id((String) body.get("binder_id"));
		            accountLink.setClient_id((String) body.get("client_id"));
		            accountLink.setOrg_id((String) body.get("org_id"));

	                for (MethodWrapper methodWrapper : methodWrappers) {
	                    Method method = methodWrapper.getMethod();
                        method.invoke(this, accountLink, response);
                    }		            	            
    	        }
            } catch (SignatureException e) {
            	// response 412
            	logger.error("Unable to verify account_link_token!");
            	response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED);
            }
    	} else {
    		response.sendError(HttpServletResponse.SC_BAD_REQUEST);    		
    	} 
    	
    }
    
    /**
     * handle all incoming POST messages
     * 
     * 
     * @param chatMessage
     * @throws Exception
     */
    
    public void handlePostRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {

    	try {
    		request.setCharacterEncoding("UTF-8");
    		
    	    // read from request
    	    ServletInputStream stream = request.getInputStream();
    	    
    	    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    	    int nRead;
    	    byte[] data = new byte[1024];
    	    while ((nRead = stream.read(data, 0, data.length)) != -1) {
    	        buffer.write(data, 0, nRead);
    	    }
    	 
    	    buffer.flush();
    	    byte[] body = buffer.toByteArray();    	      	    
    	    
    	    logger.info("body: " + new String(body, "UTF-8"));
    	    
    	    if (this.isVerifyPostSignature()) {
	    		String signatureHash = request.getHeader("x-moxtra-signature");
	    	    if (StringUtils.isEmpty(signatureHash)) {
	    	    	throw new Exception("No request signature!");
	    	    }    	    	
	    	    // validate signature
	    	    try {
	    	    	String expectedHash = calculateHMAC_SHA1(body, client_secret);
	    	    	if (!signatureHash.equals(expectedHash)) {
	    	    		throw new Exception("Validation on the request signature failed! signatureHash: " + signatureHash + " expectedHash: " + expectedHash);
	    	    	}
	    	    	
	    	    } catch (Exception e) {
	    	    	logger.error(e.getMessage());
	    	    	throw e;
	    	    }
    	    }
    	    
    	    // get body to JSON object
    		ObjectMapper mapper = new ObjectMapper();
    		ChatMessage chatMessage = mapper.readValue(body, ChatMessage.class);
    		
    		List<MethodWrapper> methodWrappers = null;
    		Chat chat = null;
        	String message_type = chatMessage.getMessage_type();
   
        	switch(message_type) {
      		case "bot_enabled":
      		case "bot_disabled":
        	case "bot_installed": 
      		case "bot_uninstalled":	
      		case "page_created":
			case "file_uploaded":  	
			case "page_annotated":  	
			case "todo_created":  	
			case "todo_completed":  	
			case "meet_recording_ready":  	
				chat = new Chat(chatMessage);
    	        methodWrappers = eventToMethodsMap.get(chat.getEventType().name());
    	        if (methodWrappers != null) {
	               for (MethodWrapper methodWrapper : methodWrappers) {
	                    Method method = methodWrapper.getMethod();
                        method.invoke(this, chat);
                    }
    	        }
				break;
      	    
    	  	case "comment_posted": 
    	  	case "comment_posted_on_page":
    	  		List<Invocable> invokees = filterMessageMethods(chatMessage);
                if (invokees != null && invokees.size() > 0) {
                    for (Invocable invokee : invokees) {
                    	chat = new Chat(chatMessage);
                    	chat.setMatcher(invokee.getMatcher());
                    	chat.setPrimatches(invokee.getPrimatches());
                    	
                        Method method = invokee.getMethodWrapper().getMethod();
                        method.invoke(this, chat);
                    }
                }
    	  		break;
      	
      		case "bot_postback": 
	        	chat = new Chat(chatMessage);	
      			String postback_text = chat.getPostback().getText();
     			
    	        methodWrappers = eventToMethodsMap.get(EventType.POSTBACK.name());
    	        if (methodWrappers != null) {    	        	
	                for (MethodWrapper methodWrapper : methodWrappers) {
	            	   String text = methodWrapper.getText();
	            	   
	            	   if (!StringUtils.isEmpty(text)) {
		            	   if (postback_text != null && postback_text.equalsIgnoreCase(text)) {
			                    Method method = methodWrapper.getMethod();
		                        method.invoke(this, chat);
		            	   } 
	            	   } else {	            	   
		                    Method method = methodWrapper.getMethod(); 
	                        method.invoke(this, chat);
	            	   }
                    }
    	        }      			
      			break;        	
        	}
        	
        	response.setStatus(HttpServletResponse.SC_OK);
        	
        } catch (Exception e) {
            logger.error("Error handling Message for: " + e.getMessage(), e);
        }
    }	
    
    /**
     * invoke handler for access_token after Account_Link
     * 
     * @param request
     * @param access_token
     * @throws Exception
     */
    public void handleAccountLinkAccessToken(HttpServletRequest request, String access_token) throws Exception {
    	
    	List<MethodWrapper> methodWrappers = eventToMethodsMap.get(EventType.ACCESS_TOKEN.name());
        if (methodWrappers != null) {
           for (MethodWrapper methodWrapper : methodWrappers) {
                Method method = methodWrapper.getMethod();
                method.invoke(this, access_token, request);
            }
        }          	
    	
    }
    
    /**
     * To obtain moxtra access_token
     * 
     * @param client_id
     * @param org_id
     * @return
     */
    public Token getAccessToken(String client_id, String org_id) {
    	
    	Token token = moxtraAccessToken.get(org_id);    	
		long current = System.currentTimeMillis();  
		
    	if (token != null) {
    		// verify if still valid
    		if (current < token.getExipred_time()) {
    			return token;
    		}
    	}
    	
		RestTemplate restTemplate = new RestTemplate();
		
    	HttpHeaders headers = new HttpHeaders();
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        String sig_value = client_id + org_id + Long.toString(current);
        String signature = null;
        
        try {
        	signature = generateSignature(sig_value.getBytes(), this.client_secret);
        } catch (Exception e) {
        	logger.error("Error getting signature!", e);
        	return null;
        }
        
        String url = getApi_endpoint() + "/apps/token";
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url)
                .queryParam("client_id", client_id)
                .queryParam("org_id", org_id)
                .queryParam("timestamp", Long.toString(current))
                .queryParam("signature", signature);

        try {
            
        	ResponseEntity<String> response = restTemplate.exchange(builder.build().encode().toUri(), HttpMethod.GET, entity, String.class);
            
        	String responseBody = response.getBody();
    		ObjectMapper mapper = new ObjectMapper();
    		HashMap<String, String> value = null;
    		try {
    			value = mapper.readValue(responseBody, HashMap.class);
    			
            	token = new Token();
            	token.setAccess_token(value.get("access_token"));
        		long expires = Long.parseLong(value.get("expires_in")) * 1000L;
            	token.setExipred_time(current + expires);
        		
            	moxtraAccessToken.put(org_id, token);
            	
            	return token;
    			
            } catch (Exception e) {
            	logger.error("Error getting response!", e);
            	return null;
            }
            
        } catch (RestClientException e) {
            logger.error("Error getting access_token!", e);
            return null;
        }        	
    	
    }   
    
	// create HMac
	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}    
    
	private static byte[] encodeUrlSafe(byte[] data) {
		byte[] encode = Base64.encode(data);
	    for (int i = 0; i < encode.length; i++) {
	        if (encode[i] == '+') {
	            encode[i] = '-';
	        } else if (encode[i] == '/') {
	            encode[i] = '_';
	        } else if (encode[i] == '=') {
	        	encode[i] = ' ';
	        }
	    }
	    return encode;
	}		
	
	private static String calculateHMAC_SHA1(byte[] data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("UTF-8"), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		return "sha1=" + toHexString(mac.doFinal(data));
	}	    

	public static String generateSignature(byte[] data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes("UTF-8"), HMAC_SHA256_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
		mac.init(signingKey);
		return new String(encodeUrlSafe((mac.doFinal(data)))).trim();
	}	    
	
    private List<Invocable> filterMessageMethods(ChatMessage chatMessage) {
    	
        List<MethodWrapper> methodWrappers = eventToMethodsMap.get(EventType.MESSAGE.name());
        if (methodWrappers == null) 
        	return null;
        
        String text = chatMessage.getEvent().getComment().getText();
        
        if (StringUtils.isEmpty(text)) {
        	return null;
        }
        
        // ordered list
        List<Invocable> invokees = new LinkedList<Invocable>();
        
        // filter to get qualified methods
    	int primatches = 0;
    	
    	// with pattern
    	for (MethodWrapper methodWrapper : methodWrappers) {

            String pattern = methodWrapper.getPattern();
            
            if (!StringUtils.isEmpty(pattern)) {
                Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                Matcher m = p.matcher(text);
                if (m.find()) {
                	Invocable invokee = new Invocable(methodWrapper);
                	invokee.setMatcher(m);
                	invokee.setPrimatches(primatches);
                    invokees.add(invokee);
                    
                    primatches++;
                }
            }
        }
    	
    	// whether to invoke generic handler if no matches
    	if (primatches == 0 || this.isGenericHandling()) {
	    	// without pattern
	    	for (MethodWrapper methodWrapper : methodWrappers) {
	
	            String pattern = methodWrapper.getPattern();
	            
	            if (StringUtils.isEmpty(pattern)) {
	            	// add default handler
	            	Invocable invokee = new Invocable(methodWrapper);
	            	invokee.setPrimatches(primatches);
	            	invokees.add(invokee);
	            	
	            	primatches++;
	            }
	        }
    	}
    	
    	return invokees;
    }    
    
    /**
     * To be invoked
     *
     */    
    private class Invocable {
        private Matcher matcher;
        private int primatches = 0;
        private MethodWrapper methodWrapper;
        
        public Invocable(MethodWrapper methodWrapper) {
        	this.methodWrapper = methodWrapper;
        }

        public MethodWrapper getMethodWrapper() {
        	return methodWrapper;
        }
        
        public int getPrimatches() {
        	return primatches;
        }
        
        public void setPrimatches(int primatches) {
        	this.primatches = primatches;
        }

        public Matcher getMatcher() {
            return matcher;
        }

        public void setMatcher(Matcher matcher) {
            this.matcher = matcher;
        }
    }
    
    
    /**
     * Wrapper class for methods annotated with {@link EventHandler}.
     */
    private class MethodWrapper {
        private Method method;
        private String pattern;
        private String text; // for POSTBACK

        public Method getMethod() {
            return method;
        }

        public void setMethod(Method method) {
            this.method = method;
        }

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            MethodWrapper that = (MethodWrapper) o;

            if (!method.equals(that.method)) return false;
            if (pattern != null ? !pattern.equals(that.pattern) : that.pattern != null) return false;
            if (text != null ? !text.equals(that.text) : that.text != null) return false;
            return true;
        }

        @Override
        public int hashCode() {
            int result = method.hashCode();
            result = 31 * result + (pattern != null ? pattern.hashCode() : 0);
            result = 31 * result + (text != null ? text.hashCode() : 0);
            return result;
        }
    }
}
