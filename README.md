# Moxtra Bot SDK for Java

Moxtra Bot SDK is for building Spring Boot based application that will ease and streamline the Bot development for Moxtra's business collaboration platform. The design allows developers to focus on application logic instead of APIs for sending and receiving data payload.

```java
@Component
public class MyBot extends MoxtraBot {

  @EventHandler(event = EventType.MESSAGE)
  public void onMessage(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    String message = "Echo: @" + username + " " + text;
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }
```

| [Core Concepts][] | [Installation][] | [Getting Started][] | [Account Linking][] | [Documentation][] | [Examples][] | [License][] |
|---|---|---|---|---|---|---|

---

## Core Concepts

- Bot verification flow: before saving bot configuration during bot creation, a JSONP verification request with message_type=bot_verify&verify_token='YOUR_VERIFY_TOKEN'&  
bot_challenge='RANDOM_STRING' sending to the configured verify_url. To complete the bot creation, this request expects the same 'RANDOM_STRING' gets returned.  

- Binder based bot installation: each received message event has the corresponding *binder_id* and *access_token* for reply, which are encapsulated in the `Chat` object  

- Each `POST` message event from Moxtra has `x-moxtra-signature` header set as HMA-SHA1 hash of the message content signed with `client_secret` 

- Different message event has the corresponding object in the event; however, the basic message structure remains the same. Below shows a `Comment` message event format:
```js
{
  message_id: 'MESSAGE_ID',
  message_type: 'comment_posted',
  binder_id: 'BINDER_ID',
  bot_id: 'BOT_ID',
  access_token: 'ACCESS_TOKEN',
  event: {
    timestamp: 'TIMESTAMP',
    user: {
      id: 'USER_ID',
      name: 'USERNAME'
    },
    comment: {
      id: 'COMMENT_ID',
      text: 'TEXT MESSAGE',
      audio: 'AUDIO MESSAGE'    
    },
    target: {
      id: 'BINDER_ID',
      object_type: 'binder'
    }
  }
}
```

## Installation

You can check out Moxtra Bot SDK directly from Git to use the example code and included bots.

```bash
git clone https://github.com/Moxtra/moxtra-bot-sdk-java.git
```

## Getting Started

- Create a new bot application using your `verify_token` and `client_secret` obtained from your [MoxtraBot configuration](https://developer.moxtra.com/nextbots) and place those info in /resources/application.properties as shown below to finish the bot creation:

```
verify_token=YOUR_VERIFY_TOKEN
client_secret=YOUR_CLIENT_SECRET
```

- Set correct API endpoint if testing in the Sandbox environment:
> In the Chat.java class, change to 
> **private static final String URL_ENDPOINT = "https://apisandbox.moxtra.com/v1/messages";** from private static final String URL_ENDPOINT = "https://api.moxtra.com/v1/messages";

- Create a sub-class of `MoxtraBot` and add `@EventHandler` annotation to methods that handle messages for various events: *EventType.MESSAGE*, *EventType.BOT_INSTALLED*, *EventType.BOT_UNINSTALLED*, *EventType.POSTBACK*, and *EventType.ACCOUNT_LINK*. 

```java
@Component
public class MyBot extends MoxtraBot {

  @EventHandler(event = EventType.MESSAGE)
  public void onMessage(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    String message = "@" + username + " says " + text;
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }
  
  @EventHandler(event = EventType.BOT_INSTALLED)
  public void onBotInstalled(Chat chat) {
    String username = chat.getUsername();
    String binder_id = chat.getBinder_id();
    String access_token = chat.getAccess_token();
    
    // store binder based Moxtra access_token
    moxtraAccessToken.put(binder_id, access_token);
    
    String message = "@" + username + " Welcome to MoxtraBot!!"; 
    chat.sendRequest(new Comment.Builder().text(message).build());
  }
  
  @EventHandler(event = EventType.BOT_UNINSTALLED)
  public void onBotUninstalled(ChatMessage chatMessage) {
    String binder_id = chatMessage.getBinder_id();
    
    // remove Moxtra access_token for this binder
    moxtraAccessToken.remove(binder_id);
    
    logger.info("Bot uninstalled on {}", binder_id);
  }  
```
Other message events are *EventType.PAGE_CREATED*, *EventType.PAGE_ANNOTATED*, *EventType.FILE_UPLOADED*, *EventType.TODO_CREATED*, *EventType.TODO_COMPLETED* and *EventType.MEET_RECORDING_READY*.

- Add `@EventHandler` annotation with `patterns` attribute for method using regular expression with case-insensitive or exact keyword match:

```java
  @EventHandler(patterns = {"(schedule|plan|have)? meet", "meeting together"})
  public void onHears(Chat chat) {
    String username = chat.getUsername();
    
    logger.info("@{} said {}, {}, {}, or {}", useranme, "schedule... meet", "plan... meet", "have... meet", "meeting together");
  }  
```

- Reply to messages using the `Chat` object to send a `Comment`:

```java
  @EventHandler(patterns = {"(schedule|plan|have)? meet", "meeting together"})
  public void onHears(Chat chat) {
    String username = chat.getUsername();
    
    String message = "@" + username + " do you need to schedule a meet?";
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }  
```
>- Send Text  
>```java
>String message = "@" + username + " do you need to schedule a meet?";
>Comment comment = new Comment.Builder().text(message).build();
>chat.sendRequest(comment);
>```
>
>- Send RichText (in [BBCode](https://www.bbcode.org) style)  
>```java
>String message = "@[b]" + username + "[/b] [i][color=Blue]do you need to schedule a meet?[/color][/i]";
>Comment comment = new Comment.Builder().richtext(message).build();
>chat.sendRequest(comment);
>```
>
>- Send JSON fields (in key-value style along with a pre-configured or an on-demand template)  
>```java
>HashMap<String, String> fieldsMap = new HashMap();  
>fieldsMap.put("title", "BBCode Info");  
>fieldsMap.put("from", username);  
>fieldsMap.put("info", text);  
>fieldsMap.put("image_url", "https://www.bbcode.org/images/lubeck_small.jpg");
>
>Comment comment = new Comment.Builder().fields(fieldsMap).build();
>chat.sendRequest(comment); 
>```
>
>- Upload File or Add Audio Comment for audio file (audio/x-m4a, audio/3gpp)  
>```java
>String message = "@" + username + " upload files";
>    
>ClassLoader classLoader = getClass().getClassLoader();
>File file = new File(classLoader.getResource("file/start.png").getFile());
>File audio = new File(classLoader.getResource("file/test_comment.3gpp").getFile());    
>    
>chat.sendRequest(new Comment.Builder().text(message).build(), file, audio);
>```
>

- Matching keywords for more than once:

If there are more than one keyword matches in the method for `@EventHandler` annotation with `patterns` attribute, the same method as well as the generic method for *EventType.MESSAGE* without `patterns` attribute would get invoked. By checking `chat.getPrimatches()` to determine whether to handle in this situation. 

`Matcher matcher = chat.getMatcher();` - the word that matches the regular expression or the whole keyword can be determined by checking [Matcher](https://docs.oracle.com/javase/7/docs/api/java/util/regex/Matcher.html) group() APIs
`chat.getPrimatches()` - the number of times that match happened before 


```java
  @EventHandler(event = EventType.MESSAGE)
  public void onMessage(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    if (chat.getPrimatches() > 0) {
      logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
      return;
    }
    
    String message = "Echo: @" + username + " " + text;
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }
  
  @EventHandler(patterns = {"(schedule|plan|have)? meet", "meeting together"})
  public void onHears(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    if (chat.getPrimatches() > 0) {
      logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
      return;
    } else {
      Matcher matcher = chat.getMatcher();
      
      logger.info("message for @{} {} on {}", username, text, matcher.group(0));
    }
       
    String message = "@" + username + " do you need to schedule a meet?";
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }  
```

- Add `POSTBACK` button to the reply: 

>- `buttons` array  
>Setting desired buttons in an array which would form buttons in a single column layout 
>- `POSTBACK` object   
>&nbsp;type - "postpack"  
>&nbsp;text - required text shown on the button   
>&nbsp;payload - optional info to carry back; if not specified, it's "MOXTRABOT_text in uppercase" 
>
>- A single string can also turn into a button object; for example "Not Sure?" becomes  
>{  
>&nbsp;type: 'postpack',  
>&nbsp;text: 'Not Sure?',   
>&nbsp;payload: 'MOXTRABOT_NOT SURE?"   
>}

```java
  Button postback_button = new Button("Not Sure?");
  
  chat.sendRequest(new Comment.Builder().addButton(postback_button).build());
```

- Handle *EventType.POSTBACK* event:  

The *EventType.POSTBACK* event gets triggered when the `POSTBACK` button is tapped. The corresponding event with *text* attribute gets triggered as well.  

```java
  @EventHandler(event = EventType.POSTBACK, text = "Not Sure?")
  public void onSpecificPostback(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getPostback().getText();
    String payload = chat.getPostback().getPayload();
    
    String message = "@" + username + " specific postback " + text + " " + payload; 
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }    

  @EventHandler(event = EventType.POSTBACK)
  public void onPostback(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getPostback().getText();
    String payload = chat.getPostback().getPayload();
    
    String message = "@" + username + " generic postback " + text + " " + payload; 
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }  
```

- Set up Spring Boot Application:

You can setup your own preferred endpoints for handling `GET` and `POST` methods. In the example, we use `/webhooks` as the endpoints.  

```java
@RestController
@SpringBootApplication
public class MoxtraBotApplication {
  private static final Logger logger = LoggerFactory.getLogger(MoxtraBotApplication.class);

  @Autowired
  private MyBot bot; 
  
  // GET 
  @RequestMapping(value = "/webhooks", method = RequestMethod.GET)
  public void getRequest(HttpServletRequest request, HttpServletResponse response) {
    try {
      bot.handleGetRequest(request, response);
    } catch (Exception e) {
      logger.error(e.getMessage());
    }
  }  
  
  // POST
  @RequestMapping(value = "/webhooks", method = RequestMethod.POST)
  public void postRequest(HttpServletRequest request, HttpServletResponse response) {
    try {
      bot.handlePostRequest(request, response);
    } catch (Exception e) {
      logger.error(e.getMessage());
    }
  }  
  
  // Application  
  public static void main(String[] args) {
    SpringApplication.run(MoxtraBotApplication.class, args);
  }  
}    
```

## Account Linking

- Link Moxtra account with the 3rd party service through Account Linking flow:
>1. User sends a request to Bot, which requires access to a 3rd party service that needs user's authorization. Bot does not have prior user account linking info with the 3rd party service.
>2. Bot sends `ACCOUNT_LINK` button back to Moxtra chat.
>3. User clicks the button and a [JSON web token](https://en.wikipedia.org/wiki/JSON_Web_Token) sends back to Bot via the `GET` method.
>4. Bot verifies the token using `client_secret` as the key and decodes the token; Bot obtains *user_id*, *username*, and *binder_id* via handling the *EventType.ACCOUNT_LINK* event.
>5. Bot needs to check whether the *user_id* having the corresponding *access_token* from the 3rd party service in case `ACCOUNT_LINK` button might be tapped more than once or by different users in a group chat. If no, next OAuth2 authorization flow would then follows.
>6. After obtaining the *access_token* from the 3rd party service, Bot needs to complete the original request.

- Add `ACCOUNT_LINK` button:
```java
  Button account_link_button = new Button(Button.ACCOUNT_LINK, "Sign In");
  
  chat.sendRequest(new Comment.Builder().addButton(account_link_button).build());
```
- Handle *EventType.ACCOUNT_LINK* event:
```java
  @EventHandler(event = EventType.ACCOUNT_LINK)
  public void onAccountLink(AccountLink accountLink, HttpServletResponse response) {
    String user_id = accountLink.getUser_id();
    String binder_id = accountLink.getBinder_id();
    String username = accountLink.getUsername();
    
    // obtain pending response
    Chat chat = pendingResponse.get(binder_id + user_id);
    
    if (chat != null) {
      String message = "@" + username + " performs an account_link for user_id: " + user_id + " on binder_id: " + binder_id;
      
      chat.sendRequest(new Comment.Builder().text(message).build());  
    } else {
      chat = pendingOAuth.get(user_id);      
    }
    
    String access_token = accountLinked.get(user_id);
    
    try {
      if (access_token != null) {
        
        if (chat == null) {
          logger.info("Unable to get pending request!");  
          
          String bot_access_token = moxtraAccessToken.get(binder_id);

          // create a new Chat
          if (bot_access_token != null) {
            chat = new Chat();
            chat.setAccess_token(bot_access_token);
          }
        }
        
        if (chat != null) {
          String message = "@" + username + " has already obtained access_token from the 3rd party service!";
          
          chat.sendRequest(new Comment.Builder().text(message).build());
        }

        // close window
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.print("<html><head></head><body onload=\"javascript:window.close();\"></body></html>");
        out.flush();
        
      } else {
  
        pendingResponse.remove(binder_id + user_id);
  
        // save chat to the pendingOAuth 
        pendingOAuth.put(user_id, chat);
  
        // redirect if needed  
        Cookie myCookie = new Cookie("user_id", user_id);
        response.addCookie(myCookie);
          
        response.sendRedirect("/auth");        
      }
    } catch (Exception e) {
      logger.error("Unable to handle account_link: " + e.getMessage());
    }      
  }    
```
- Handle OAuth2 flow:

Setup OAuth2 configuration in /resources/application.properties as shown below:

```java
oauth2_client_id=SERVICE_OAUTH2_CLIENT_ID
oauth2_client_secret=SERVICE_OAUTH2_CLIENT_SECRET
oauth2_endpoint=SERVICE_OAUTH2_ENDPOINT
oauth2_auth_path=SERVICE_OAUTH2_AUTH_PATH
oauth2_token_path=SERVICE_OAUTH2_TOKEN_PATH
oauth2_redirect_uri=SERVICE_OAUTH2_DIRECT_URI
```

Handle OAuth2 in Spring Boot Application:

```java
  // OAuth2  
  @Autowired
  private OAuth2 oauth2; 

  // Auth
  @RequestMapping(value = "/auth", method = RequestMethod.GET)
  public void authRequest(HttpServletRequest request, HttpServletResponse response) {
    oauth2.auth(request, response);
  }  
  
  // Callback
  @RequestMapping(value = "/callback", method = RequestMethod.GET)
  public void redirectRequest(HttpServletRequest request, HttpServletResponse response) {
    oauth2.callback(request, response, bot);
  }  
```

- Obtain `access_token` via catching *EventType.ACCESS_TOKEN* event 

```java
  // after doing OAuth2 against the 3rd party service to obtain a user level access_token
  @EventHandler(event = EventType.ACCESS_TOKEN)
  public void onAccessToken(String access_token, HttpServletRequest request) {

    String user_id = null;
    Cookie[] cookies = request.getCookies();
    for (Cookie cookie : cookies) {

      if (cookie.getName().equals("user_id")) {
        user_id = cookie.getValue();
        break;
      }
    }    
    
    Chat chat = null;
    if (user_id != null) {
      chat = pendingOAuth.get(user_id);    
      
      // save linked accessToken
      accountLinked.put(user_id, access_token);
    }
    
    if (chat != null) {
      
      pendingOAuth.remove(user_id);

      // complete the pending request
      String username = chat.getUsername();
      String text = chat.getComment().getText();
      
      String message = "@" + username + " after account linked, bot will complete your request: " + text;
      
      chat.sendRequest(new Comment.Builder().text(message).build());        
    }    
  }    
```

## Documentation

### MoxtraBot Class

#### `abstract class MoxtraBot`

| `configuration` key | Type | Required |
|:--------------|:-----|:---------|
| `verify_token` | string | `Y` |
| `client_secret` | string | `Y` |

Creates a new `MoxtraBot` instance. 

---

### MoxtraBot Event Annotation


#### `@EventHandler`

Subscribe to the message event emitted by the bot, and a callback gets invoked with the parameter pertaining to the event type. Available events are:

| Event | Callback Parameters | Description |
|:------|:-----|:-----|
| *EventType.BOT_INSTALLED* | Chat object - EventBot: chat.getBot() | The user installed the bot in one binder |
| *EventType.BOT_UNINSTALLED* | ChatMessage object | The user removed the bot from the binder |
| *EventType.MESSAGE* | Chat object - EventComment: chat.getComment() | The bot received a text message from the user by commenting in a binder |
| *EventType.POSTBACK* | Chat object - EventPostback: chat.getPostback() | The bot received a postback call from the user after  clicking a `POSTBACK` button |
| *EventType.ACCOUNT_LINK* | AccountLink object, Response | The bot received an account_link call from the user after clicking an `ACCOUNT_LINK` button |
| *EventType.PAGE_CREATED* | Chat object - EventPage: chat.getPage() | The bot received a message that a page was created in the binder |
| *EventType.FILE_UPLOADED* | Chat object - EventFile: chat.getFile() | The bot received a message that a file was uploaded in the binder |
| *EventType.PAGE_ANNOTATED* | Chat object - EventAnnotate: chat.getAnnotate() | The bot received a message that an annotation was created on a page in the binder |
| *EventType.TODO_CREATED* | Chat object - EventTodo: chat.getTodo() | The bot received a message that a todo item was created in the binder |
| *EventType.TODO_COMPLETED* | Chat object - EventTodo: chat.getTodo() | The bot received a message that a todo item was completed in the binder |
| *EventType.MEET_RECORDING_READY* | Chat object - EventMeet:  chat.getMeet() | The bot received a message that a meet recording was ready in the binder |

##### Example:

```java
  @EventHandler(event = EventType.MESSAGE)
  public void onMessage(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    if (chat.getPrimatches() > 0) {
      logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
      return;
    }
    
    StringBuilder richtext = new StringBuilder();
    richtext.append("[table][tr][th][center]BBCode Info[/center][/th][/tr]");
    richtext.append("[tr][td][img=50x25]https://www.bbcode.org/images/lubeck_small.jpg[/img][/td][/tr][tr][td]From: [i]");
    richtext.append(username);
    richtext.append("[/i][/td][/tr][tr][td][color=Red]");
    richtext.append(text);
    richtext.append("[/color][/td][/tr][/table]");  
    
    chat.sendRequest(new Comment.Builder().richtext(richtext.toString()).build());
  }

  @EventHandler(event = EventType.POSTBACK)
  public void onPostback(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getPostback().getText();
    String payload = chat.getPostback().getPayload();
    
    String message = "@" + username + " generic postback " + text + " " + payload; 
    
    chat.sendRequest(new Comment.Builder().text(message).build());
  }  
```

#### `@EventHandler with patterns attribute`

Using pattern matching mechanism to handle desired message. The `patterns` param can be a string, a regex or an array of both strings and regexs that find matching against the received message. If a match was found, the callback gets invoked. At the same time, `EventType.MESSAGE` event also gets fired.  `chat.getPrimatches()` needs to be checked in such case.

##### Example:

```java
  @EventHandler(patterns = {"(schedule|plan|have)? meet", "meeting together"})
  public void onHears(Chat chat) {
    String username = chat.getUsername();
    String text = chat.getComment().getText();
    
    if (chat.getPrimatches() > 0) {
      logger.info("message has been handled: @{} {} for {} times", username, text, chat.getPrimatches());
      return;
    } else {
      Matcher matcher = chat.getMatcher();
      
      logger.info("message for @{} {} on {}", username, text, matcher.group(0));
    }
    
    // save chat in pendingResponse for account_link
    pendingResponse.put(chat.getBinder_id() + chat.getUser_id(), chat);
    
    Button account_link_button = new Button(Button.ACCOUNT_LINK, "Sign In");
    Button postback_button = new Button("Not Sure?");
    
    String message = "@" + username + " do you need to schedule a meet?";
    
    chat.sendRequest(new Comment.Builder().text(message).addButton(account_link_button)
        .addButton(postback_button).build());
  }  
```
---

### Chat Class and API

#### `new Chat(ChatMessage)`

Chat instance is created in the callback for each type of message event except *EventType.BOT_UNINSTALLED* and *EventType.ACCOUNT_LINK*. Therefore, chat.getBinder_id(), chat.getUser_id(), chat.getUsername(), and chat.getAccess_token() as well as corresponding event object are pre-populated.  

A typical `Chat` instance has the following structure:

```java
{
  private String user_id;
  private String username;
  private String binder_id;
  private String access_token;
  private int primatches = 0;  // NUMBER_OF_MATCHES_BEFORE
  private Matcher matcher;     // MATCHED_KEYWORD
  private EventType eventType;
  private ChatMessage chatMessage;

  // sendRequest API
  public boolean sendRequest(Comment comment) {    
  };
  // sendRequest API for Upload File and Add Audio Comment for audio file (audio/x-m4a, audio/3gpp)
  public boolean sendRequest(Comment comment, File file, File audio) {    
  };
  // getBinderInfo API
  public String getBinderInfo() {    
  };
  // getUserInfo API
  public String getUserInfo() {    
  }; 
}
```
#### `getBinderInfo()`

This API is to get the installed binder information, which can use the `access_token` obtained on the *EventType.BOT_INSTALLED* event.  

##### Example:

```java
Chat chat = new Chat();
chat.setAccess_token(access_token);

String binder_info = chat.getBinderInfo();
```
##### Result:

```java
{
  "code": "RESPONSE_SUCCESS",
  "data": {
    "id": "BiHGjPE2ZbsHyhVujuU4TUL",
    "name": "test bot",
    "created_time": 1487787567445,
    "updated_time": 1491598936463,
    "total_comments": 0,
    "total_members": 8,
    "total_pages": 0,
    "total_todos": 0,
    "revision": 884,
    "thumbnail_uri": "https://www.moxtra.com/board/BiHGjPE2ZbsHyhVujuU4TUL/4",
    "conversation": false,
    "users": [],
    "restricted": false,
    "team": false,
    "description": "",
    "feeds_timestamp": 1491598936463,
    "status": "BOARD_MEMBER",
    "last_feed": null,
    "binder_email": "b2f583d00339e44d0b2d02f9d50f352fa",
    "tags": null,
    "unread_feeds": 0,
    "pages": []
  }
}
```

#### `getUserInfo()`

This API is to get the specific user information in the binder, which can use the `access_token` obtained on the *EventType.BOT_INSTALLED* event.  

##### Example:

```java
Chat chat = new Chat();
chat.setAccess_token(access_token);
chat.setUser_id(user_id);

String user_info = chat.getUserInfo();
```
##### Result:

```java
{
  "code": "RESPONSE_SUCCESS",
  "data": {
    "id": "Utkj3YC5BxRHCCbq9widP67",
    "email": "john@test.com",
    "name": "John Smith",
    "picture_uri": "https://www.moxtra.com/board/BiHGjPE2ZbsHyhVujuU4TUL/user/2/1763",
    "phone_number": "",
    "unique_id": ""
  }
}
```

### ChatMessage Class

```
  private String message_id;
  private String message_type;
  private String binder_id;
  private String bot_id;
  private String access_token;
  private Event event;
```  
  
#### `EventBot` Class for `EventType.BOT_INSTALLED`
```
  private String id;    // BOT_ID
  private String name;  // BOT_NAME
```    
#### `EventComment` Class for `EventType.MESSAGE`
```
  private String id;        // COMMENT_ID
  private String text;      // TEXT MESSAGE
  private String richtext;  // RICHTEXT MESSAGE
  private String audio;     // AUDIO MESSAGE
```  
#### `EventPostback` Class for `EventType.POSTBACK`
```
  private String text;     // POSTBACK_TEXT
  private String payload;  // POSTBACK_PAYLOAD
```  
#### `EventPage` Class for `EventType.PAGE_CREATED`
```
  private String id;    // PAGE_ID
  private String type;  // PAGE_TYPE
```  
#### `EventAnnotate` Class for `EventType.PAGE_ANNOTATED`
```
  private String id;    // PAGE_ID
```  
#### `EventFile` Class for `EventType.FILE_UPLOADED`
```
  private String id;    // FILE_ID
  private String name;  // FILE_NAME
```   
#### `EventTodo` Class for `EventType.TODO_CREATED` and `EventType.TODO_COMPLETED`
```
  private String id;    // TODO_ID
  private String name;  // TODO_ITEM_NAME
```     
#### `EventMeet` Class for `EventType.MEET_RECORDING_READY`
```
  private String id;             // MEET_ID
  private String topic;          // MEET_TOPIC
  private String recording_url;  // MEET_RECORDING_URL
  private String start_time;     // MEET_START_TIME
  private String end_time;       // MEET_END_TIME  
```  

### Comment Class

Comment object is used for setting up messages for sending via `Chat` and is generated through Comment.Builder(), which has the following structure:

```java
  private String text;                    // TEXT
  private String richtext;                // RICHTEXT
  private HashMap<String, String> fields; // JSON FIELDS
  private String action;                  // on-demand action for chat, page, or todo
  private List<Button> buttons;           // BUTTONS 
  public Builder text(String text) {
  };
  public Builder richtext(String richtext) {
  };
  public Builder fields(HashMap<String, String> fields) {
  };
  public Builder action(String action) {
  };
  public Builder addButton(Button button) {
  };
  public Builder addTemplate(Template template) {
  };
  public Comment build() {
  };  
```  

#### `Button` Class

```java
  private String type;     // POSTBACK or ACCOUNT_LINK
  private String text;     // TEXT
  private String payload;  // PAYLOAD
```

#### `Template` Class

`Template` specifies on-demand fields_template array, which is used in setting JSON `fields` message with corresponding action type. 

```java
  private String template_type;  // TEXT, RICHTEXT, or PAGE
  private String template;       // TEMPLATE
```
##### Example:

```java
  HashMap<String, String> fieldsMap = new HashMap();  
  fieldsMap.put("title", "BBCode Info");  
  fieldsMap.put("from", username);  
  fieldsMap.put("info", text);  
  fieldsMap.put("image_url", "https://www.bbcode.org/images/lubeck_small.jpg");
  
  Comment comment = new Comment.Builder().fields(fieldsMap).build();
  
  chat.sendRequest(comment); 
```

---

## Examples

Check the `examples` directory to see the example of the following capabilities:

- Send text message
- Using regular expression to capture text message
- Sending RichText message
- Sending Fields message
- Upload file and add audio comment
- Handling Account Link with OAuth2 

To run the examples, make sure to complete the bot creation on [MoxtraBot configuration](https://developer.moxtra.com/nextbots) and setup required configurations in /resources/application.properties. There are many ways to run the example, below is using Maven plugin:

```
$ mvn spring-boot:run
```

## License

MIT

[Core Concepts]:#core-concepts
[Installation]:#installation
[Getting Started]:#getting-started
[Account Linking]:#account-linking
[Documentation]:#documentation
[Examples]:#examples
[License]:#license
