package com.moxtra.bot.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.moxtra.bot.model.EventType;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface EventHandler {
    EventType event() default EventType.MESSAGE;
    
    String[] patterns() default {};
    
    String text() default "";    // for POSTBACK
}
