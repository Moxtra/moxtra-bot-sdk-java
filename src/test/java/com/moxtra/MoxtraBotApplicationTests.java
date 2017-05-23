package com.moxtra;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
@WebAppConfiguration
public class MoxtraBotApplicationTests {

	@Autowired
	private WebApplicationContext webContext;
	
	private MockMvc mockmvc;
	
	@Before
	public void setupMockMvc() {
		mockmvc = MockMvcBuilders.webAppContextSetup(webContext).build();
	}
		
	@Test
	public void contextLoads() {
	}

}
