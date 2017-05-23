package com.moxtra.bot;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.moxtra.examples.MyBot;

@Component
public class OAuth2 {
	private static final Logger logger = LoggerFactory.getLogger(OAuth2.class);

	@Value("${oauth2.client_id:OAUTH2_CLIENT_ID}")
	private String oauth2_client_id;
	
	@Value("${oauth2.client_secret:OAUTH2_CLIENT_SECRET}")
	private String oauth2_client_secret;
		
	@Value("${oauth2.authorizeUrl:OAUTH2_AUTHORIZE_URL}")
	private String oauth2_authorizeUrl;

	@Value("${oauth2.tokenUrl:OAUTH2_TOKEN_URL}")
	private String oauth2_tokenUrl;
	
	@Value("${oauth2.redirectUri:OAUTH2_REDIRECT_URI}")
	private String oauth2_redirectUri;    

	
	public void auth(HttpServletRequest request, HttpServletResponse response) {
		try {
			OAuthClientRequest auth_request = OAuthClientRequest
				.authorizationLocation(oauth2_authorizeUrl)
				.setResponseType("code")
				.setClientId(oauth2_client_id)
				.setRedirectURI(oauth2_redirectUri)
				.buildQueryMessage();			
				
			response.sendRedirect(auth_request.getLocationUri());		
			
			logger.info("oauth auth_url: " + auth_request.getLocationUri());
			
		} catch (Exception e) {
			logger.error(e.getMessage());
		}		
	}
	
	
	public void callback(HttpServletRequest request, HttpServletResponse response, MoxtraBot bot) {
		try {

			OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String code = oar.getCode();
			
			OAuthClientRequest auth_request = OAuthClientRequest
                .tokenLocation(oauth2_tokenUrl)
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId(oauth2_client_id)
                .setClientSecret(oauth2_client_secret)
                .setRedirectURI(oauth2_redirectUri)
                .setCode(code)
                .buildQueryMessage();
			
			OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
			
            String access_token =
            	oAuthClient.accessToken(auth_request, OAuthJSONAccessTokenResponse.class)
                .getAccessToken();
			
            logger.info("oauth access_token: " + access_token);
            
            bot.handleAccessToken(request, response, access_token);
			
		} catch (Exception e) {
			logger.error(e.getMessage());
		}		
	}
	
}
